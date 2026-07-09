rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    match /saloes/{salonId} {
      allow read: if request.auth != null && request.auth.uid == salonId;
      allow create: if request.auth != null && request.auth.uid == salonId;
      allow update: if request.auth != null
        && request.auth.uid == salonId
        && !camposSensiveisAlterados(request.resource.data, resource.data);
      allow delete: if false;
    }

    match /funcionarios/{profId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      // Criar e apagar profissional agora só pelo backend (Admin SDK, via
      // /adicionarProfissional e /removerProfissional) — é lá que o contador
      // profissionaisAtivos é atualizado de forma confiável.
      allow create, delete: if false;
      // Editar nome/especialidade/foto de um profissional já existente
      // continua liberado pro dono do salão — não afeta limite de plano.
      allow update: if request.auth != null
        && resource.data.salonId == request.auth.uid
        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['salonId']);
    }

    match /agendamentos/{appointmentId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.salonId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.salonId == request.auth.uid;
    }

    match /servicos/{servicoId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.salonId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.salonId == request.auth.uid;
    }

    match /despesas/{despesaId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.salonId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.salonId == request.auth.uid;
    }

    match /estoque/{estoqueId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.salonId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.salonId == request.auth.uid;
    }

    match /estoque_movimentacoes/{movId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.salonId == request.auth.uid;
      allow update, delete: if request.auth != null && resource.data.salonId == request.auth.uid;
    }

    match /alugueis/{aluguelId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      // Só o backend cria (rotina automática via Admin SDK, que ignora estas regras).
      allow create, delete: if false;
      // O dono do salão só pode marcar como pago — não pode mudar valor,
      // competência ou de qual profissional é a cobrança.
      allow update: if request.auth != null
        && resource.data.salonId == request.auth.uid
        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['salonId', 'profissionalId', 'valor', 'competencia', 'criadoEm']);
    }

    match /cobrancas/{cobrancaId} {
      allow read: if request.auth != null && resource.data.salonId == request.auth.uid;
      // Só o backend cria (precisa chamar a API do Mercado Pago) e só o
      // webhook marca como paga — nada disso pode ser feito pelo cliente.
      allow create, update, delete: if false;
    }

    match /faq_videos/{faqId} {
      // Qualquer usuário logado pode ler (é só conteúdo de ajuda, sem dado sensível).
      allow read: if request.auth != null;
      // Só o e-mail do administrador do CorteZap pode cadastrar/editar vídeos —
      // reforça no banco o que a tela já esconde visualmente.
      allow write: if request.auth != null && request.auth.token.email == 'extracred7@gmail.com';
    }

    match /mp_conexoes/{salonId} {
      // Guarda access_token/refresh_token de cada salão — NINGUÉM lê ou
      // escreve isso pelo cliente, nem o próprio dono. Só o backend (Admin
      // SDK) mexe aqui, na troca de OAuth e na renovação de token.
      allow read, write: if false;
    }

    // Campos que só o backend (Admin SDK / webhook) pode alterar.
    // O Admin SDK ignora estas regras, então isso só bloqueia o CLIENTE.
    function camposSensiveisAlterados(novos, atual) {
      let protegidos = ['status', 'plano', 'periodo', 'assinaturaId',
                        'profissionaisAtivos', 'proximaCobranca', 'assinaturaAtivaEm'];
      return novos.diff(atual).affectedKeys().hasAny(protegidos);
    }

  }
}
