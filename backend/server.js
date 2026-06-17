const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================================
// OWASP A05 - Security Misconfiguration: Helmet
// Esconde headers que revelam tecnologia do servidor,
// adiciona proteções contra XSS, clickjacking, etc.
// ============================================================
app.use(helmet());

// ============================================================
// OWASP A01 - Broken Access Control: CORS Restrito
// Só aceita requisições vindas do domínio do frontend.
// ============================================================
const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(url => url.trim())
  : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5500'];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requisições sem origin (ex: mobile apps, curl em dev)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Bloqueado pela política de CORS'));
  },
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

// ============================================================
// Rate Limiting: Proteção contra DoS e abuso
// 50 requisições por IP a cada 15 minutos
// ============================================================
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em alguns minutos.' },
});
app.use('/api/', limiter);

// Parse JSON body (com limite de tamanho para prevenir ataques)
app.use(express.json({ limit: '100kb' }));

// ============================================================
// OWASP A10 - SSRF Prevention
// URLs dos provedores são HARDCODED — nunca vêm do usuário.
// ============================================================
const PROVIDERS = {
  openai: {
    baseURL: 'https://api.openai.com/v1',
    getKey: () => process.env.OPENAI_API_KEY,
  },
  deepinfra: {
    baseURL: 'https://api.deepinfra.com/v1/openai',
    getKey: () => process.env.DEEPINFRA_API_KEY,
  },
  openrouter: {
    baseURL: 'https://openrouter.ai/api/v1',
    getKey: () => process.env.OPENROUTER_API_KEY,
  },
};

// Lista de prefixos de modelos por provedor (OWASP A10 - previne SSRF)
const DEEPINFRA_PREFIXES = [
  'mistralai/', 'meta-llama/', '01-ai/', 'openchat/', 'lizpreciatior/',
  'deepinfra/', 'Phind/', 'jondurbin/', 'codellama/', 'Gryphe/',
  'amazon/', 'codellama/',
];

const OPENROUTER_PREFIXES = [
  'google/', 'anthropic/', 'perplexity/',
];

/**
 * Determina o provedor com base no nome do modelo.
 * Nunca aceita URLs do usuário (OWASP A10).
 */
function getProviderForModel(modelName) {
  if (!modelName || typeof modelName !== 'string') return null;

  // Modelos OpenAI (começam com gpt- ou tts-)
  if (modelName.startsWith('gpt-') || modelName.startsWith('tts-')) {
    return 'openai';
  }

  // Modelos DeepInfra
  for (const prefix of DEEPINFRA_PREFIXES) {
    if (modelName.startsWith(prefix)) return 'deepinfra';
  }

  // Modelos OpenRouter
  for (const prefix of OPENROUTER_PREFIXES) {
    if (modelName.startsWith(prefix)) return 'openrouter';
  }

  // Fallback: se tem "/" mas não é reconhecido, tenta deepinfra
  if (modelName.includes('/')) return 'deepinfra';

  // Default: OpenAI
  return 'openai';
}

/**
 * Cria uma instância do cliente OpenAI para o provedor correto.
 */
function createClient(providerName) {
  const provider = PROVIDERS[providerName];
  if (!provider) throw new Error('Provedor desconhecido');

  const apiKey = provider.getKey();
  if (!apiKey) throw new Error(`Chave de API não configurada para ${providerName}`);

  return new OpenAI({
    apiKey: apiKey,
    baseURL: provider.baseURL,
  });
}

// ============================================================
// Endpoint: POST /api/chat
// Proxy para chat completions (OpenAI, DeepInfra, OpenRouter)
// ============================================================
app.post('/api/chat', async (req, res) => {
  try {
    const { model, messages, temperature } = req.body;

    // OWASP A03 - Injection: Validação de Input
    if (!model || typeof model !== 'string') {
      return res.status(400).json({ error: 'Campo "model" é obrigatório.' });
    }
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Campo "messages" é obrigatório e deve ser uma lista.' });
    }
    if (temperature !== undefined && (typeof temperature !== 'number' || temperature < 0 || temperature > 2)) {
      return res.status(400).json({ error: 'Campo "temperature" deve ser um número entre 0 e 2.' });
    }

    // Validar cada mensagem
    for (const msg of messages) {
      if (!msg.role || !['system', 'user', 'assistant'].includes(msg.role)) {
        return res.status(400).json({ error: 'Cada mensagem deve ter um "role" válido (system, user, assistant).' });
      }
      if (typeof msg.content !== 'string') {
        return res.status(400).json({ error: 'Cada mensagem deve ter um "content" do tipo texto.' });
      }
    }

    const providerName = getProviderForModel(model);
    const client = createClient(providerName);

    const params = {
      model: model,
      messages: messages,
    };
    if (temperature !== undefined) {
      params.temperature = temperature;
    }

    const completion = await client.chat.completions.create(params);

    return res.json({
      choices: completion.choices,
      model: completion.model,
      usage: completion.usage,
    });

  } catch (error) {
    console.error('[/api/chat] Erro:', error.message);
    // OWASP 2025 - Mishandling Exceptions: nunca vazar stacktrace
    return res.status(500).json({ error: 'Erro ao processar a requisição. Tente novamente.' });
  }
});

// ============================================================
// Endpoint: POST /api/speech
// Proxy para text-to-speech (OpenAI TTS)
// ============================================================
app.post('/api/speech', async (req, res) => {
  try {
    const { text, voice } = req.body;

    // Validação de Input
    if (!text || typeof text !== 'string' || text.length === 0) {
      return res.status(400).json({ error: 'Campo "text" é obrigatório.' });
    }
    if (text.length > 4096) {
      return res.status(400).json({ error: 'Texto muito longo (máximo 4096 caracteres).' });
    }
    if (!voice || typeof voice !== 'string') {
      return res.status(400).json({ error: 'Campo "voice" é obrigatório.' });
    }
    const allowedVoices = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];
    if (!allowedVoices.includes(voice)) {
      return res.status(400).json({ error: `Voz "${voice}" não é válida.` });
    }

    const client = createClient('openai');

    const mp3Response = await client.audio.speech.create({
      model: 'tts-1',
      voice: voice,
      response_format: 'mp3',
      input: text,
    });

    const buffer = Buffer.from(await mp3Response.arrayBuffer());

    res.set({
      'Content-Type': 'audio/mpeg',
      'Content-Length': buffer.length,
    });
    return res.send(buffer);

  } catch (error) {
    console.error('[/api/speech] Erro:', error.message);
    return res.status(500).json({ error: 'Erro ao gerar áudio. Tente novamente.' });
  }
});

// ============================================================
// Endpoint: POST /api/verify
// Proxy para verificação de informações
// ============================================================
app.post('/api/verify', async (req, res) => {
  try {
    const { text, model, temperature } = req.body;

    // Validação de Input
    if (!text || typeof text !== 'string' || text.length === 0) {
      return res.status(400).json({ error: 'Campo "text" é obrigatório.' });
    }
    if (!model || typeof model !== 'string') {
      return res.status(400).json({ error: 'Campo "model" é obrigatório.' });
    }

    const providerName = getProviderForModel(model);
    const client = createClient(providerName);

    const systemInstructions = '';
    const userMessagePrompt = 'You will be my assistant in verifying information to know if it is real facts or not. You must identify whether the information is false news or an incorrect statement. You should look for information that conflicts with the text provided, look for known information that is incompatible with the text provided. You must write a reflection of at least 5 lines analyzing the information to find out whether it is true or not and then you will skip a line and give a final verdict on the result. Check the following information:\n';

    const messages = [
      { role: 'system', content: systemInstructions },
      { role: 'user', content: userMessagePrompt + text },
    ];

    const params = {
      model: model,
      messages: messages,
      temperature: typeof temperature === 'number' ? temperature : 0.25,
    };

    const completion = await client.chat.completions.create(params);
    const textResponse = completion.choices[0].message.content;

    return res.json({ result: textResponse });

  } catch (error) {
    console.error('[/api/verify] Erro:', error.message);
    return res.status(500).json({ error: 'Erro ao verificar informação. Tente novamente.' });
  }
});

// ============================================================
// Health check (útil para o Render e keep-alive)
// ============================================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// OWASP 2025 - Mishandling Exceptions: Global Error Handler
// Captura qualquer erro não tratado e retorna mensagem genérica.
// ============================================================
app.use((err, req, res, next) => {
  console.error('[Global Error]', err.message);
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

// ============================================================
// Iniciar servidor
// ============================================================
app.listen(PORT, () => {
  console.log(`[zillaGPT Backend] Servidor rodando na porta ${PORT}`);
  console.log(`[zillaGPT Backend] CORS permitido para: ${allowedOrigins.join(', ')}`);
});
