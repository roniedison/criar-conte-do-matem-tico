# MathRPG

Aplicativo local de aprendizagem de matemática com missões, áreas de estudo, módulos e atividades interativas. Inclui contas individuais, pontuação separada por usuário e painel administrativo para controle de acesso.

## Executar

Com Node.js instalado, na pasta do projeto:

```powershell
node server.js
```

Abra `http://localhost:8766` no navegador e crie a primeira conta. A primeira conta recebe o perfil de administrador; as contas seguintes são estudantes e ficam pendentes até aprovação. No painel de acompanhamento, o administrador consulta o progresso, libera ou desativa acessos e pode excluir contas. Cada progresso é gravado no servidor em `data/users.json`; as senhas são armazenadas como hashes.

## Arquivos

- `index.html`: interface do aplicativo.
- `styles.css`: estilos e layout responsivo.
- `app.js`: atividades, correção, progresso, XP e relatórios.
- `server.js`: servidor local, autenticação e API de progresso/controle de acesso.
- `data/users.json`: banco local de contas e progresso, criado na primeira execução.
