# Importa wraps para criar o decorador de login obrigatório.
from functools import wraps

# Importa as ferramentas do Flask usadas no sistema.
# Flask: cria a aplicação.
# render_template: abre os arquivos HTML da pasta templates.
# request: recebe dados enviados pelos formulários.
# redirect: redireciona o usuário para outra rota.
# url_for: gera a URL pelo nome da função da rota.
# flash: mostra mensagens temporárias na tela.
# session: guarda os dados do usuário logado.
from flask import Flask, render_template, request, redirect, url_for, flash, session

# Importa funções de segurança para conferir senha com hash, caso exista senha criptografada.
# O sistema também aceita senha em texto puro, pois seu banco atual está assim.
from werkzeug.security import check_password_hash

# Importa as funções do arquivo db.py.
# iniciar_bd: cria o banco e as tabelas se não existirem.
# execute_query: executa comandos SQL e também SELECT com fetch=True.
# execute_one: retorna apenas um registro do SELECT.
from db import iniciar_bd, execute_query, execute_one

# Cria a aplicação Flask.
app = Flask(__name__)

# Chave secreta usada pelo Flask para session e flash.
app.secret_key = 'gamestore_chave_secreta'

# Inicializa o banco de dados ao iniciar a aplicação.
iniciar_bd()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def senha_confere(senha_salva, senha_digitada):
    """
    Confere a senha do usuário.
    Se a senha estiver criptografada, usa check_password_hash.
    Se estiver em texto puro, compara normalmente.
    Isso evita erro com os usuários antigos do seu banco.
    """
    if not senha_salva:
        return False

    # Senhas criptografadas pelo Werkzeug normalmente começam assim.
    if senha_salva.startswith('scrypt:') or senha_salva.startswith('pbkdf2:'):
        return check_password_hash(senha_salva, senha_digitada)

    # Senha em texto puro, igual está no seu banco agora.
    return senha_salva == senha_digitada


def login_obrigatorio(f):
    """
    Bloqueia o acesso às páginas internas.
    Se não houver usuário logado, manda para a tela de login.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Você precisa estar logado para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def injetar_usuario():
    """
    Injeta a variável usuario_logado em todos os templates.
    Assim o HTML pode saber se existe usuário logado.
    """
    return dict(usuario_logado=session.get('usuario_nome'))


# ─────────────────────────────────────────────
# ROTAS PÚBLICAS
# ─────────────────────────────────────────────

@app.route('/')
def index():
    """Página inicial pública."""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Exibe a tela de login e autentica o usuário."""

    # Se já estiver logado, manda direto para usuários.
    if 'usuario_id' in session:
        return redirect(url_for('listar_usuarios'))

    # Se o formulário foi enviado.
    if request.method == 'POST':

        # Pega e-mail e senha digitados.
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '').strip()

        # Validação simples para não consultar vazio.
        if not email or not senha:
            flash('Preencha e-mail e senha.', 'danger')
            return render_template('login.html')

        # Busca o usuário pelo e-mail.
        usuario = execute_one(
            'SELECT * FROM usuarios WHERE email = %s',
            (email,)
        )

        # Se não encontrou o usuário ou a senha não confere.
        if usuario is None or not senha_confere(usuario['senha'], senha):
            flash('E-mail ou senha inválidos.', 'danger')
            return render_template('login.html')

        # Salva dados do usuário na sessão.
        session['usuario_id'] = usuario['id_usuario']
        session['usuario_nome'] = usuario['nome']
        session['usuario_email'] = usuario['email']

        # Após login correto, envia para a lista de usuários.
        return redirect(url_for('listar_usuarios'))

    # Se for GET, apenas mostra a tela.
    return render_template('login.html')


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """Exibe a tela de cadastro e salva um novo usuário."""

    # Se o formulário foi enviado.
    if request.method == 'POST':

        # Pega os dados do formulário.
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '').strip()
        confirmar = request.form.get('confirmar', '').strip()

        # Confere campos obrigatórios.
        if not nome or not email or not senha or not confirmar:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('cadastro.html')

        # Confere se as senhas são iguais.
        if senha != confirmar:
            flash('As senhas não conferem.', 'danger')
            return render_template('cadastro.html')

        # Verifica se o e-mail já existe.
        usuario_existente = execute_one(
            'SELECT id_usuario FROM usuarios WHERE email = %s',
            (email,)
        )

        if usuario_existente:
            flash('Este e-mail já está cadastrado.', 'danger')
            return render_template('cadastro.html')

        # Cadastra o usuário no banco.
        # A senha fica em texto puro para manter compatibilidade com seu banco atual.
        execute_query(
            '''
            INSERT INTO usuarios
            (
                nome,
                email,
                senha,
                perfil
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )
            ''',
            (
                nome,
                email,
                senha,
                'Colecionador'
            )
        )

        flash('Cadastro realizado com sucesso. Faça login.', 'success')
        return redirect(url_for('login'))

    # Se for GET, apenas mostra a tela.
    return render_template('cadastro.html')


@app.route('/logout')
def logout():
    """Sai do sistema limpando os dados da sessão."""
    session.clear()
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

@app.route('/home')
@login_obrigatorio
def home():
    """Página inicial interna. Por enquanto redireciona para usuários."""
    return redirect(url_for('listar_usuarios'))


# ─────────────────────────────────────────────
# USUÁRIOS
# ─────────────────────────────────────────────

@app.route('/usuarios/listar')
@login_obrigatorio
def listar_usuarios():
    """Lista todos os usuários cadastrados."""

    lista = execute_query(
        'SELECT * FROM usuarios ORDER BY id_usuario DESC',
        fetch=True
    )

    # Os templates usam u.id, então criamos um apelido para id_usuario.
    usuarios = [
        {**u, 'id': u['id_usuario']}
        for u in lista
    ]

    return render_template('usuarios/listar_usuarios.html', usuarios=usuarios)


@app.route('/usuarios/inserir', methods=['GET', 'POST'])
@login_obrigatorio
def inserir_usuario():
    """Exibe o formulário e cadastra um usuário pelo painel."""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        perfil = request.form.get('perfil', '').strip()
        senha = request.form.get('senha', '').strip()

        if not nome or not email or not perfil or not senha:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('usuarios/inserir_usuario.html')

        existente = execute_one(
            'SELECT id_usuario FROM usuarios WHERE email = %s',
            (email,)
        )

        if existente:
            flash('Este e-mail já está cadastrado.', 'danger')
            return render_template('usuarios/inserir_usuario.html')

        execute_query(
            'INSERT INTO usuarios (nome, email, senha, perfil) VALUES (%s, %s, %s, %s)',
            (nome, email, senha, perfil)
        )

        flash('Usuário cadastrado com sucesso.', 'success')
        return redirect(url_for('listar_usuarios'))

    return render_template('usuarios/inserir_usuario.html')


@app.route('/usuarios/editar/<int:uid>', methods=['GET', 'POST'])
@login_obrigatorio
def editar_usuario(uid):
    """Edita um usuário existente."""

    usuario = execute_one(
        'SELECT * FROM usuarios WHERE id_usuario = %s',
        (uid,)
    )

    if usuario is None:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('listar_usuarios'))

    # O template usa usuario.id.
    usuario = {**usuario, 'id': usuario['id_usuario']}

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        perfil = request.form.get('perfil', '').strip()

        if not nome or not email or not perfil:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('usuarios/editar_usuario.html', usuario=usuario)

        execute_query(
            'UPDATE usuarios SET nome = %s, email = %s, perfil = %s WHERE id_usuario = %s',
            (nome, email, perfil, uid)
        )

        flash('Usuário atualizado com sucesso.', 'success')
        return redirect(url_for('listar_usuarios'))

    return render_template('usuarios/editar_usuario.html', usuario=usuario)


@app.route('/usuarios/excluir/<int:uid>', methods=['POST'])
@login_obrigatorio
def excluir_usuario(uid):
    """Exclui um usuário."""

    if session.get('usuario_id') == uid:
        flash('Você não pode excluir seu próprio usuário.', 'danger')
        return redirect(url_for('listar_usuarios'))

    execute_query(
        'DELETE FROM usuarios WHERE id_usuario = %s',
        (uid,)
    )

    flash('Usuário excluído com sucesso.', 'success')
    return redirect(url_for('listar_usuarios'))


# ─────────────────────────────────────────────
# JOGOS
# ─────────────────────────────────────────────

@app.route('/jogos/listar')
@login_obrigatorio
def listar_jogos():
    """Lista todos os jogos cadastrados."""

    lista = execute_query(
        'SELECT * FROM jogos ORDER BY id_jogo DESC',
        fetch=True
    )

    # Os templates usam j.id, então criamos um apelido para id_jogo.
    jogos = [
        {**j, 'id': j['id_jogo']}
        for j in lista
    ]

    return render_template('jogos/listar_jogos.html', jogos=jogos)


@app.route('/jogos/inserir', methods=['GET', 'POST'])
@login_obrigatorio
def inserir_jogo():
    """Exibe o formulário e cadastra um jogo."""

    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        genero = request.form.get('genero', '').strip()
        ano = request.form.get('ano', '').strip()
        plataforma = request.form.get('plataforma', '').strip()
        nota = request.form.get('nota', '').strip()

        if not titulo or not genero or not ano or not plataforma or not nota:
            flash('Todos os campos são obrigatórios.', 'danger')
            plataformas = execute_query('SELECT * FROM plataformas ORDER BY nome', fetch=True)
            return render_template('jogos/inserir_jogo.html', plataformas=plataformas)

        execute_query(
            'INSERT INTO jogos (titulo, genero, ano, plataforma, nota) VALUES (%s, %s, %s, %s, %s)',
            (titulo, genero, int(ano), plataforma, int(nota))
        )

        flash('Jogo cadastrado com sucesso.', 'success')
        return redirect(url_for('listar_jogos'))

    plataformas = execute_query('SELECT * FROM plataformas ORDER BY nome', fetch=True)
    return render_template('jogos/inserir_jogo.html', plataformas=plataformas)


@app.route('/jogos/editar/<int:jid>', methods=['GET', 'POST'])
@login_obrigatorio
def editar_jogo(jid):
    """Edita um jogo existente."""

    jogo = execute_one(
        'SELECT * FROM jogos WHERE id_jogo = %s',
        (jid,)
    )

    if jogo is None:
        flash('Jogo não encontrado.', 'danger')
        return redirect(url_for('listar_jogos'))

    jogo = {**jogo, 'id': jogo['id_jogo']}

    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        genero = request.form.get('genero', '').strip()
        ano = request.form.get('ano', '').strip()
        plataforma = request.form.get('plataforma', '').strip()
        nota = request.form.get('nota', '').strip()

        if not titulo or not genero or not ano or not plataforma or not nota:
            flash('Todos os campos são obrigatórios.', 'danger')
            plataformas = execute_query('SELECT * FROM plataformas ORDER BY nome', fetch=True)
            return render_template('jogos/editar_jogo.html', jogo=jogo, plataformas=plataformas)

        execute_query(
            'UPDATE jogos SET titulo = %s, genero = %s, ano = %s, plataforma = %s, nota = %s WHERE id_jogo = %s',
            (titulo, genero, int(ano), plataforma, int(nota), jid)
        )

        flash('Jogo atualizado com sucesso.', 'success')
        return redirect(url_for('listar_jogos'))

    plataformas = execute_query('SELECT * FROM plataformas ORDER BY nome', fetch=True)
    return render_template('jogos/editar_jogo.html', jogo=jogo, plataformas=plataformas)


@app.route('/jogos/excluir/<int:jid>', methods=['POST'])
@login_obrigatorio
def excluir_jogo(jid):
    """Exclui um jogo."""

    execute_query(
        'DELETE FROM jogos WHERE id_jogo = %s',
        (jid,)
    )

    flash('Jogo excluído com sucesso.', 'success')
    return redirect(url_for('listar_jogos'))


# ─────────────────────────────────────────────
# FUNÇÕES
# ─────────────────────────────────────────────

@app.route('/funcoes/listar')
@login_obrigatorio
def listar_funcoes():
    """Lista todas as funções cadastradas."""

    lista = execute_query(
        'SELECT * FROM funcoes ORDER BY id_funcao DESC',
        fetch=True
    )

    # Os templates usam p.id, então criamos um apelido para id_funcao.
    funcoes = [
        {**f, 'id': f['id_funcao']}
        for f in lista
    ]

    return render_template('funcoes/listar_funcoes.html', funcoes=funcoes)


@app.route('/funcoes/inserir', methods=['GET', 'POST'])
@login_obrigatorio
def inserir_funcao():
    """Exibe o formulário e cadastra uma função."""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        descricao = request.form.get('descricao', '').strip()

        # Em alguns templates o status vem como select; em outros vem como checkbox.
        status_form = request.form.get('status')
        status = status_form if status_form in ('Ativo', 'Inativo') else ('Ativo' if status_form else 'Inativo')

        gerenciar_usuarios = 1 if request.form.get('gerenciar_usuarios') else 0
        gerenciar_funcoes = 1 if request.form.get('gerenciar_funcoes') else 0
        gerenciar_jogos = 1 if request.form.get('gerenciar_jogos') else 0
        gerenciar_plataformas = 1 if request.form.get('gerenciar_plataformas') else 0

        if not nome:
            flash('O nome da função é obrigatório.', 'danger')
            return render_template('funcoes/inserir_funcao.html')

        execute_query(
            '''
            INSERT INTO funcoes
            (nome, status, descricao, gerenciar_usuarios, gerenciar_funcoes, gerenciar_jogos, gerenciar_plataformas)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''',
            (nome, status, descricao, gerenciar_usuarios, gerenciar_funcoes, gerenciar_jogos, gerenciar_plataformas)
        )

        flash('Função cadastrada com sucesso.', 'success')
        return redirect(url_for('listar_funcoes'))

    return render_template('funcoes/inserir_funcao.html')


@app.route('/funcoes/editar/<int:fid>', methods=['GET', 'POST'])
@login_obrigatorio
def editar_funcao(fid):
    """Edita uma função existente."""

    funcao = execute_one(
        'SELECT * FROM funcoes WHERE id_funcao = %s',
        (fid,)
    )

    if funcao is None:
        flash('Função não encontrada.', 'danger')
        return redirect(url_for('listar_funcoes'))

    funcao = {**funcao, 'id': funcao['id_funcao']}

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        descricao = request.form.get('descricao', '').strip()

        status_form = request.form.get('status')
        status = status_form if status_form in ('Ativo', 'Inativo') else ('Ativo' if status_form else 'Inativo')

        gerenciar_usuarios = 1 if request.form.get('gerenciar_usuarios') else 0
        gerenciar_funcoes = 1 if request.form.get('gerenciar_funcoes') else 0
        gerenciar_jogos = 1 if request.form.get('gerenciar_jogos') else 0
        gerenciar_plataformas = 1 if request.form.get('gerenciar_plataformas') else 0

        if not nome:
            flash('O nome da função é obrigatório.', 'danger')
            return render_template('funcoes/editar_funcao.html', funcao=funcao)

        execute_query(
            '''
            UPDATE funcoes
            SET nome = %s,
                status = %s,
                descricao = %s,
                gerenciar_usuarios = %s,
                gerenciar_funcoes = %s,
                gerenciar_jogos = %s,
                gerenciar_plataformas = %s
            WHERE id_funcao = %s
            ''',
            (nome, status, descricao, gerenciar_usuarios, gerenciar_funcoes, gerenciar_jogos, gerenciar_plataformas, fid)
        )

        flash('Função atualizada com sucesso.', 'success')
        return redirect(url_for('listar_funcoes'))

    return render_template('funcoes/editar_funcao.html', funcao=funcao)


@app.route('/funcoes/excluir/<int:fid>', methods=['POST'])
@login_obrigatorio
def excluir_funcao(fid):
    """Exclui uma função."""

    execute_query(
        'DELETE FROM funcoes WHERE id_funcao = %s',
        (fid,)
    )

    flash('Função excluída com sucesso.', 'success')
    return redirect(url_for('listar_funcoes'))


# ─────────────────────────────────────────────
# PLATAFORMAS
# ─────────────────────────────────────────────

@app.route('/plataformas/listar')
@login_obrigatorio
def listar_plataformas():
    """Lista todas as plataformas cadastradas."""

    lista = execute_query(
        'SELECT * FROM plataformas ORDER BY id_plataforma DESC',
        fetch=True
    )

    # Os templates usam p.id, então criamos um apelido para id_plataforma.
    plataformas = [
        {**p, 'id': p['id_plataforma']}
        for p in lista
    ]

    return render_template('plataformas/listar_plataformas.html', plataformas=plataformas)


@app.route('/plataformas/inserir', methods=['GET', 'POST'])
@login_obrigatorio
def inserir_plataforma():
    """Exibe o formulário e cadastra uma plataforma."""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        fabricante = request.form.get('fabricante', '').strip()
        tipo = request.form.get('tipo', '').strip()
        ano_lancamento = request.form.get('ano_lancamento', '').strip()
        jogos_disponiveis = request.form.get('jogos_disponiveis', '0').strip()

        if not nome or not fabricante or not tipo or not ano_lancamento:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('plataformas/inserir_plataforma.html')

        execute_query(
            '''
            INSERT INTO plataformas (nome, fabricante, ano_lancamento, tipo, jogos_disponiveis)
            VALUES (%s, %s, %s, %s, %s)
            ''',
            (nome, fabricante, int(ano_lancamento), tipo, int(jogos_disponiveis or 0))
        )

        flash('Plataforma cadastrada com sucesso.', 'success')
        return redirect(url_for('listar_plataformas'))

    return render_template('plataformas/inserir_plataforma.html')


@app.route('/plataformas/editar/<int:pid>', methods=['GET', 'POST'])
@login_obrigatorio
def editar_plataforma(pid):
    """Edita uma plataforma existente."""

    plataforma = execute_one(
        'SELECT * FROM plataformas WHERE id_plataforma = %s',
        (pid,)
    )

    if plataforma is None:
        flash('Plataforma não encontrada.', 'danger')
        return redirect(url_for('listar_plataformas'))

    plataforma = {**plataforma, 'id': plataforma['id_plataforma']}

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        fabricante = request.form.get('fabricante', '').strip()
        tipo = request.form.get('tipo', '').strip()
        ano_lancamento = request.form.get('ano_lancamento', '').strip()
        jogos_disponiveis = request.form.get('jogos_disponiveis', '0').strip()

        if not nome or not fabricante or not tipo or not ano_lancamento:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('plataformas/editar_plataforma.html', plataforma=plataforma)

        execute_query(
            '''
            UPDATE plataformas
            SET nome = %s,
                fabricante = %s,
                ano_lancamento = %s,
                tipo = %s,
                jogos_disponiveis = %s
            WHERE id_plataforma = %s
            ''',
            (nome, fabricante, int(ano_lancamento), tipo, int(jogos_disponiveis or 0), pid)
        )

        flash('Plataforma atualizada com sucesso.', 'success')
        return redirect(url_for('listar_plataformas'))

    return render_template('plataformas/editar_plataforma.html', plataforma=plataforma)


@app.route('/plataformas/excluir/<int:pid>', methods=['POST'])
@login_obrigatorio
def excluir_plataforma(pid):
    """Exclui uma plataforma."""

    execute_query(
        'DELETE FROM plataformas WHERE id_plataforma = %s',
        (pid,)
    )

    flash('Plataforma excluída com sucesso.', 'success')
    return redirect(url_for('listar_plataformas'))


# ─────────────────────────────────────────────
# EQUIPE
# ─────────────────────────────────────────────

@app.route('/equipe')
def equipe():
    """Página pública da equipe."""
    return render_template('sobre_equipe.html')


# Inicia o servidor de desenvolvimento.
if __name__ == '__main__':
    app.run(debug=True)
