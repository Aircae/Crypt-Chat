import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 处理WebSocket请求
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader === 'websocket') {
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 处理API请求
    if (url.pathname.startsWith('/api/')) {
      // ...API 逻辑...
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }

    // 处理认证页面请求
    if (url.pathname === '/auth') {
      return this.handleAuthRequest(request, env);
    }

    // 检查是否需要访问验证
    const requiresAuth = env.REQUIRE_AUTH === 'true';
    const authPassword = env.AUTH_PASSWORD;
    
    // 如果启用了访问验证，检查访问权限
    if (requiresAuth && authPassword) {
      const isAuthenticated = await this.checkAuthentication(request, authPassword, env);
      
      if (!isAuthenticated) {
        // 如果请求的是静态资源，直接放行
        if (url.pathname.startsWith('/assets/') || url.pathname.endsWith('.css') || url.pathname.endsWith('.js') || url.pathname.endsWith('.ico')) {
          // 交给 ASSETS 处理
        } else {
          // 重定向到登录页面
          const authUrl = new URL('/auth', request.url);
          authUrl.searchParams.set('return', url.pathname + url.search);
          return Response.redirect(authUrl.toString(), 302);
        }
      }
    }

    // 其余全部交给 ASSETS 处理（自动支持 hash 文件名和 SPA fallback）
    return env.ASSETS.fetch(request);
  },

  // 处理认证请求
  async handleAuthRequest(request, env) {
    const url = new URL(request.url);
    
    // 检查是否已启用访问验证
    if (env.REQUIRE_AUTH !== 'true' || !env.AUTH_PASSWORD) {
      // 未启用验证，重定向到首页
      return Response.redirect(new URL('/', request.url).toString(), 302);
    }

    // 如果是POST请求，处理登录
    if (request.method === 'POST') {
      try {
        const formData = await request.formData();
        const password = formData.get('password');
        const returnPath = formData.get('return') || '/';
        
        if (password === env.AUTH_PASSWORD) {
          // 生成认证令牌
          const authToken = await this.generateAuthToken(password, env);
          
          // 设置Cookie并重定向
          const headers = new Headers({
            'Location': returnPath,
            'Set-Cookie': `chat_auth_token=${authToken}; Path=/; HttpOnly; SameSite=Lax; Secure`
          });
          
          return new Response(null, {
            status: 302,
            headers
          });
        } else {
          // 密码错误，重新显示登录页面
          return this.renderAuthPage('密码错误，请重试。', returnPath);
        }
      } catch (error) {
        console.error('Login error:', error);
        return this.renderAuthPage('登录过程中发生错误。', '/');
      }
    }
    
    // GET请求，显示登录页面
    const returnPath = url.searchParams.get('return') || '/';
    return this.renderAuthPage(null, returnPath);
  },

  // 检查认证状态
  async checkAuthentication(request, authPassword, env) {
    try {
      // 从Cookie中获取认证令牌
      const cookieHeader = request.headers.get('Cookie');
      if (cookieHeader) {
        const cookies = this.parseCookies(cookieHeader);
        const authToken = cookies['chat_auth_token'];
        
        if (authToken) {
          // 验证令牌
          const expectedToken = await this.generateAuthToken(authPassword, env);
          return authToken === expectedToken;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Authentication check error:', error);
      return false;
    }
  },

  // 解析Cookie
  parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;
    
    cookieHeader.split(';').forEach(cookie => {
      const [key, ...valueParts] = cookie.trim().split('=');
      const value = valueParts.join('='); // 处理包含等号的值
      if (key) cookies[key] = decodeURIComponent(value);
    });
    
    return cookies;
  },

  // 生成认证令牌
  async generateAuthToken(password, env) {
    try {
      // 使用环境变量中的密钥生成更安全的令牌
      const secret = env.AUTH_SECRET || 'default-secret-change-this';
      const encoder = new TextEncoder();
      const data = encoder.encode(password + secret);
      
      // 使用SHA-256生成哈希
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      return hashHex.substring(0, 32); // 返回32字符的令牌
    } catch (error) {
      console.error('Token generation error:', error);
      // 回退到简单base64编码
      return btoa(password).replace(/=/g, '');
    }
  },

  // 渲染认证页面
  renderAuthPage(errorMessage = null, returnPath = '/') {
    const html = `
      <!DOCTYPE html>
      <html lang="zh-CN">
      <head>
        <meta charset="UTF-8">
		<link rel="icon" type="image/svg+xml" href="../client/assets/favicon.svg">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>访问验证</title>
        <style>
		  * {
			box-sizing: border-box;
			margin: 0;
			padding: 0;  
		  }
		  
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
          }
          
          .auth-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 100%;
            max-width: 400px;
          }
          
          h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
            font-weight: 600;
          }
          
          .form-group {
            margin-bottom: 20px;
          }
          
          label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
          }
          
          input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
          }
          
          input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
          }
          
          .error-message {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
            border: 1px solid #fcc;
          }
          
          .submit-btn {
            background: #30a8f7;
            color: white;
            border: none;
            padding: 14px 20px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
          }
          
          .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(0,0,0,0.1);
          }
          
          .submit-btn:active {
            transform: translateY(0);
          }
          
          .info-text {
            text-align: center;
            color: #666;
            margin-top: 20px;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="auth-container">
          <h1><svg t="1765106605710" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="4590" width="64" height="64"><path d="M973.85984 237.64992c-40.42752-2.7904-81.06496-10.38336-115.92192-21.54496-11.28448-3.39456-22.5792-7.15264-33.94048-11.22304-23.95648-7.05536-56.54528-21.04832-93.53216-40.9856-0.39936-0.1792-0.78848-0.40448-1.1776-0.6144-8.69888-4.69504-17.59744-9.70752-26.6496-15.0272-12.20608-6.99392-24.2944-14.44864-36.36224-22.22592-0.46592-0.31744-0.92672-0.59392-1.38752-0.90112-8.66816-5.59616-17.30048-11.38176-25.86624-17.3824-5.57056-3.82464-11.15648-7.90016-16.7424-11.94496-4.19328-3.07712-8.3968-5.96992-12.5952-9.14432C578.9696 63.7184 548.64896 37.97504 520.25856 10.24c-28.3904 27.73504-58.72128 53.4784-89.43616 76.42624-4.19328 3.1744-8.40192 6.0672-12.5952 9.14432-5.59104 4.0448-11.16672 8.1152-16.7424 11.94496-8.57088 6.00064-17.19808 11.78112-25.86624 17.3824-0.45568 0.3072-0.92672 0.58368-1.3824 0.90112-12.07296 7.77728-24.15104 15.232-36.36224 22.22592-9.0624 5.31968-17.95584 10.33216-26.65472 15.0272-0.38912 0.20992-0.78848 0.4352-1.17248 0.6144-36.98688 19.9424-69.58592 33.93024-93.53728 40.9856-11.35616 4.07552-22.64064 7.82848-33.94048 11.22304-34.85696 11.1616-75.47904 18.75456-115.9168 21.54496L66.56 237.66016c1.1776 18.1248 2.39616 42.1632 3.8144 68.18816 0.22016 0 0.4864 0 0.74752-0.03584 6.82496 97.13664 26.2912 235.30496 55.65952 316.4928 1.31584 3.54304 2.432 7.2448 3.74784 10.75712 0.61952 1.65376 1.34144 3.17952 1.96096 4.81792 70.2976 181.48864 192.39424 313.53856 339.12832 361.94304l0 0.50688c19.39456 6.4 35.73248 10.35776 48.64 12.84096 12.89728-2.48832 29.25056-6.44096 48.64-12.84096l0-0.50688c146.73408-48.40448 268.8256-180.4544 339.12832-361.94304 0.61952-1.64864 1.34144-3.16416 1.96608-4.81792 1.3056-3.51232 2.432-7.20896 3.74272-10.75712 29.36832-81.18272 48.83968-219.35616 55.66464-316.4928 0.26624 0.03584 0.53248 0.03584 0.74752 0.03584 1.41312-26.02496 2.62656-50.05824 3.80416-68.18816L973.85984 237.66016 973.85984 237.64992zM920.81664 284.57472l-0.56832 10.63936c-0.57856 2.42688-0.96256 4.90496-1.14176 7.41888-6.35392 90.4192-24.20736 224.44544-52.95104 303.90272-0.79872 2.1504-1.54624 4.35712-2.2784 6.54848-0.4608 1.36704-0.91648 2.7392-1.61792 4.5312-0.5888 1.38752-1.16224 2.7648-1.55136 3.80416-65.36192 168.7296-177.76128 290.21184-308.3776 333.30176-2.11456 0.6912-4.15744 1.52064-6.11328 2.4576-8.8576 2.76992-17.54624 5.13536-25.9584 7.06048-8.35584-1.91488-16.9984-4.27008-25.84576-7.02464-1.99168-0.96256-4.06016-1.79712-6.21056-2.49344-130.62656-43.08992-243.0208-164.57216-308.25984-332.98944-0.512-1.35168-1.05472-2.66752-1.8944-4.64384-0.49664-1.32096-0.94208-2.67776-1.39776-4.0448-0.74752-2.19648-1.49504-4.4032-2.16576-6.22592-28.8512-79.744-46.69952-213.77536-53.04832-304.1792-0.17408-2.51904-0.5632-5.00736-1.152-7.43936l-0.55808-10.41408c-0.09216-1.67424-0.1792-3.33312-0.26624-4.98688 27.57632-4.25984 54.17984-10.41408 78.35648-18.16064 11.34592-3.40992 22.86592-7.20896 35.18464-11.5968 28.23168-8.48896 63.21152-23.77216 101.33504-44.27776 0.66048-0.33792 1.29536-0.67584 1.85344-0.98304 9.216-4.97152 18.64704-10.28608 27.78624-15.65184 11.99616-6.87104 24.6272-14.58688 38.61504-23.59808 0.39424-0.25088 1.07008-0.68608 1.45408-0.9472 9.1904-5.93408 18.34496-12.06784 27.01312-18.14528 5.0944-3.49184 10.1888-7.168 15.29344-10.86976l2.7392-1.97632 4.52096-3.26656c2.8928-2.06336 5.78048-4.14208 8.44288-6.15424 20.03968-14.97088 39.51104-30.7456 58.21952-47.17568 18.69312 16.4096 38.10816 32.1536 58.01984 47.02208 2.87232 2.16576 5.73952 4.22912 8.61184 6.28736l4.79232 3.456 1.7408 1.25952c5.3504 3.88096 10.71104 7.7568 15.62624 11.12064 9.09312 6.3744 18.25792 12.51328 26.57792 17.87904l2.304 1.50528c13.87008 8.93952 26.50112 16.66048 38.15936 23.33696 9.60512 5.63712 19.03616 10.95168 28.02176 15.7952 0.44544 0.24064 1.06496 0.56832 1.72032 0.90624 38.26688 20.61312 73.39008 35.96288 101.71392 44.48256 12.33408 4.39296 23.81824 8.18176 34.2528 11.30496 24.77568 7.93088 51.59936 14.1568 79.27296 18.44736C920.99072 281.3696 920.90368 282.96704 920.81664 284.57472L920.81664 284.57472zM742.20544 398.90432l-262.45632 269.0048-134.35904-137.72288c-9.30816-9.52832-24.38656-9.52832-33.69472 0-9.30816 9.5488-9.30816 25.00096 0 34.54464l151.20896 154.98752c4.65408 4.77184 10.74688 7.15776 16.8448 7.15776s12.19072-2.39104 16.84992-7.15776l279.30624-286.26944c9.30304-9.53856 9.30304-24.99584 0-34.53952C766.592 389.36576 751.5136 389.36576 742.20544 398.90432L742.20544 398.90432z" fill="#262536" p-id="4591"></path></svg></h1>
          
          ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
          
          <form method="POST" action="/auth">
            <input type="hidden" name="return" value="${returnPath}">
            
            <div class="form-group">
              <label for="password">访问密码</label>
              <input type="password" id="password" name="password" required 
                     placeholder="请输入访问密码" autocomplete="current-password" autofocus>
            </div>
            
            <button type="submit" class="submit-btn">进入聊天室</button>
          </form>
          
          <div class="info-text">
            请输入管理员提供的密码以访问聊天室
          </div>
        </div>
      </body>
      </html>
    `;
    
    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
    });
  }
};

export class ChatRoom {  constructor(state, env) {
    this.state = state;
    
    // Use objects like original server.js instead of Maps
    this.clients = {};
    this.channels = {};
    
    this.config = {
      seenTimeout: 60000,
      debug: false
    };
    
    // Initialize RSA key pair
    this.initRSAKeyPair();
  }

  async initRSAKeyPair() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        console.log('Generating new RSA keypair...');
          const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['sign', 'verify']
        );

        // 并行导出公钥和私钥以提高性能
        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
          crypto.subtle.exportKey('spki', keyPair.publicKey),
          crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
        ]);
        
        stored = {
          rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
          rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)),
          createdAt: Date.now() // 记录密钥创建时间，用于后续判断是否需要轮换
        };
        
        await this.state.storage.put('rsaKeyPair', stored);
        console.log('RSA key pair generated and stored');
      }
      
      // Reconstruct the private key
      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);
        
        stored.rsaPrivate = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBuffer,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
          },
          false,
          ['sign']
        );      }
        this.keyPair = stored;
      
      // 检查密钥是否需要轮换（如果已创建超过6小时）
      if (stored.createdAt && (Date.now() - stored.createdAt > 6 * 60 * 60 * 1000)) {
        // 如果没有任何客户端，则执行密钥轮换
        if (Object.keys(this.clients).length === 0) {
          console.log('密钥已使用6小时，进行轮换...');
          await this.state.storage.delete('rsaKeyPair');
          this.keyPair = null;
          await this.initRSAKeyPair();
        } else {
          // 否则标记需要在客户端全部断开后进行轮换
          await this.state.storage.put('pendingKeyRotation', true);
        }
      }
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
      throw error;
    }
  }

  async fetch(request) {
    // Check for WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    // Ensure RSA keys are initialized
    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    // Accept the WebSocket connection
    this.handleSession(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }  // WebSocket connection event handler
  async handleSession(connection) {    connection.accept();

    // 清理旧连接
    await this.cleanupOldConnections();

    const clientId = generateClientId();

    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection);
      return;
    }

    logEvent('connection', clientId, 'debug');    // Store client information
    this.clients[clientId] = {
      connection: connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null
    };

    // Send RSA public key
    try {
      logEvent('sending-public-key', clientId, 'debug');
      this.sendMessage(connection, JSON.stringify({
        type: 'server-key',
        key: this.keyPair.rsaPublic
      }));
    } catch (error) {
      logEvent('sending-public-key', error, 'error');
    }    // Handle messages
    connection.addEventListener('message', async (event) => {
      const message = event.data;

      if (!isString(message) || !this.clients[clientId]) {
        return;
      }

      this.clients[clientId].seen = getTime();

      if (message === 'ping') {
        this.sendMessage(connection, 'pong');
        return;
      }

      logEvent('message', [clientId, message], 'debug');      // Handle key exchange
      if (!this.clients[clientId].shared && message.length < 2048) {
        try {
          // Generate ECDH key pair using P-384 curve (equivalent to secp384r1)
          const keys = await crypto.subtle.generateKey(
            {
              name: 'ECDH',
              namedCurve: 'P-384'
            },
            true,
            ['deriveBits', 'deriveKey']
          );

          const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);
          
          // Sign the public key using PKCS1 padding (compatible with original)
          const signature = await crypto.subtle.sign(
            {
              name: 'RSASSA-PKCS1-v1_5'
            },
            this.keyPair.rsaPrivate,
            publicKeyBuffer
          );

          // Convert hex string to Uint8Array for client public key
          const clientPublicKeyHex = message;
          const clientPublicKeyBytes = new Uint8Array(clientPublicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
          
          // Import client's public key
          const clientPublicKey = await crypto.subtle.importKey(
            'raw',
            clientPublicKeyBytes,
            { name: 'ECDH', namedCurve: 'P-384' },
            false,
            []
          );

          // Derive shared secret bits (equivalent to computeSecret in Node.js)
          const sharedSecretBits = await crypto.subtle.deriveBits(
            {
              name: 'ECDH',
              public: clientPublicKey
            },
            keys.privateKey,
            384 // P-384 produces 48 bytes (384 bits)
          );          // Take bytes 8-40 (32 bytes) for AES-256 key
          this.clients[clientId].shared = new Uint8Array(sharedSecretBits).slice(8, 40);

          const response = Array.from(new Uint8Array(publicKeyBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('') + 
            '|' + btoa(String.fromCharCode(...new Uint8Array(signature)));
          
          this.sendMessage(connection, response);

        } catch (error) {
          logEvent('message-key', [clientId, error], 'error');
          this.closeConnection(connection);
        }

        return;
      }

      // Handle encrypted messages
      if (this.clients[clientId].shared && message.length <= (8 * 1024 * 1024)) {
        this.processEncryptedMessage(clientId, message);
      }
    });    // Handle connection close
    connection.addEventListener('close', async (event) => {
      logEvent('close', [clientId, event], 'debug');

      const channel = this.clients[clientId].channel;

      if (channel && this.channels[channel]) {
        this.channels[channel].splice(this.channels[channel].indexOf(clientId), 1);

        if (this.channels[channel].length === 0) {
          delete(this.channels[channel]);
        } else {
          try {
            const members = this.channels[channel];

            for (const member of members) {
              const client = this.clients[member];              if (this.isClientInChannel(client, channel)) {
                this.sendMessage(client.connection, encryptMessage({
                  a: 'l',
                  p: members.filter((value) => {
                    return (value !== member ? true : false);
                  })
                }, client.shared));
              }
            }

          } catch (error) {
            logEvent('close-list', [clientId, error], 'error');
          }
        }
      }

      if (this.clients[clientId]) {
        delete(this.clients[clientId]);
      }
    });
  }
  // Process encrypted messages
  processEncryptedMessage(clientId, message) {
    let decrypted = null;

    try {
      decrypted = decryptMessage(message, this.clients[clientId].shared);

      logEvent('message-decrypted', [clientId, decrypted], 'debug');

      if (!isObject(decrypted) || !isString(decrypted.a)) {
        return;
      }

      const action = decrypted.a;

      if (action === 'j') {
        this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        this.handleChannelMessage(clientId, decrypted);
      }

    } catch (error) {
      logEvent('process-encrypted-message', [clientId, error], 'error');
    } finally {
      decrypted = null;
    }
  }
  // Handle channel join requests
  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = decrypted.p;

      this.clients[clientId].channel = channel;

      if (!this.channels[channel]) {
        this.channels[channel] = [clientId];
      } else {
        this.channels[channel].push(clientId);
      }

      this.broadcastMemberList(channel);

    } catch (error) {
      logEvent('message-join', [clientId, error], 'error');
    }
  }
  // Handle client messages
  handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = this.clients[clientId].channel;
      const targetClient = this.clients[decrypted.c];

      if (this.isClientInChannel(targetClient, channel)) {
        const messageObj = {
          a: 'c',
          p: decrypted.p,
          c: clientId
        };

        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-client', [clientId, error], 'error');
    }
  }  // Handle channel messages
  handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) {
      return;
    }
    
    try {
      const channel = this.clients[clientId].channel;
      // 过滤有效的目标成员
      const validMembers = Object.keys(decrypted.p).filter(member => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });

      // 处理所有有效的目标成员
      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const messageObj = {
          a: 'c',
          p: decrypted.p[member],
          c: clientId
        };        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-channel', [clientId, error], 'error');
    }
  }
  // Broadcast member list to channel
  broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];

      for (const member of members) {
        const client = this.clients[member];

        if (this.isClientInChannel(client, channel)) {
          const messageObj = {
            a: 'l',
            p: members.filter((value) => {
              return (value !== member ? true : false);
            })
          };

          const encrypted = encryptMessage(messageObj, client.shared);
          this.sendMessage(client.connection, encrypted);

          messageObj.p = null;
        }
      }
    } catch (error) {
      logEvent('broadcast-member-list', error, 'error');
    }
  }  // Check if client is in channel
  isClientInChannel(client, channel) {
    return (
      client &&
      client.connection &&
      client.shared &&
      client.channel &&
      client.channel === channel ?
      true :
      false
    );
  }
  // Send message helper
  sendMessage(connection, message) {
    try {
      // In Cloudflare Workers, WebSocket.READY_STATE_OPEN is 1
      if (connection.readyState === 1) {
        connection.send(message);
      }
    } catch (error) {
      logEvent('sendMessage', error, 'error');
    }
  }  // Close connection helper
  closeConnection(connection) {
    try {
      connection.close();    } catch (error) {
      logEvent('closeConnection', error, 'error');
    }
  }
  
  // 连接清理方法
  async cleanupOldConnections() {
    const seenThreshold = getTime() - this.config.seenTimeout;
    const clientsToRemove = [];

    // 先收集需要移除的客户端，避免在迭代时修改对象
    for (const clientId in this.clients) {
      if (this.clients[clientId].seen < seenThreshold) {
        clientsToRemove.push(clientId);
      }
    }

    // 然后一次性移除所有过期客户端
    for (const clientId of clientsToRemove) {
      try {
        logEvent('connection-seen', clientId, 'debug');
        this.clients[clientId].connection.close();
        delete this.clients[clientId];
      } catch (error) {
        logEvent('connection-seen', error, 'error');      }
    }
    
    // 如果没有任何客户端和房间，检查是否需要轮换密钥
    if (Object.keys(this.clients).length === 0 && Object.keys(this.channels).length === 0) {
      const pendingRotation = await this.state.storage.get('pendingKeyRotation');
      if (pendingRotation) {
        console.log('没有活跃客户端或房间，执行密钥轮换...');
        await this.state.storage.delete('rsaKeyPair');        await this.state.storage.delete('pendingKeyRotation');
        this.keyPair = null;
        await this.initRSAKeyPair();
      }
    }
    
    return clientsToRemove.length; // 返回清理的连接数量
  }
}
