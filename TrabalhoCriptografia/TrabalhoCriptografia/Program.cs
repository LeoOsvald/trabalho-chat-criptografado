using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

// Configurações
string ip = "localhost";
int port = 8080;
bool isServer = args.Contains("--server");

if (isServer)
{

    var a = IPAddress.Loopback;
    // Modo Servidor
    var listener = new TcpListener(a, port);
    listener.Start();
    Console.WriteLine($"Servidor ouvindo em {ip}:{port}... (CTRL+C para sair)");

    var client = listener.AcceptTcpClient();
    Console.WriteLine("Cliente conectado!");

    // Gera chaves
    using var aes = Aes.Create();
    aes.KeySize = 256;
    var hmacKey = RandomNumberGenerator.GetBytes(32);

    // Envia chaves
    var stream = client.GetStream();
    stream.Write(aes.Key);
    stream.Write(aes.IV);
    stream.Write(hmacKey);

    ChatLoop(stream, aes, hmacKey);
}
else
{
    // Modo Cliente
    Console.WriteLine($"Conectando ao servidor {ip}:{port}...");
    var client = new TcpClient(ip, port);
    var stream = client.GetStream();

    // Recebe chaves
    using var aes = Aes.Create();
    aes.Key = ReadBytes(stream, 32);
    aes.IV = ReadBytes(stream, 16);
    var hmacKey = ReadBytes(stream, 32);

    Console.WriteLine("Conectado! Digite suas mensagens:");
    ChatLoop(stream, aes, hmacKey);
}

void ChatLoop(NetworkStream stream, Aes aes, byte[] hmacKey)
{
    try
    {
        while (true)
        {
            if (Console.KeyAvailable)
            {
                // Envia mensagem
                Console.Write("Você: ");
                var msg = Console.ReadLine() ?? "";

                aes.GenerateIV();
                var encrypted = Encrypt(msg, aes, hmacKey);

                // Exibe a mensagem criptografada (em Base64 para legibilidade)
                Console.WriteLine($"[INTERCEPTADO] Mensagem criptografada (Base64): {Convert.ToBase64String(encrypted)}");

                stream.Write(encrypted, 0, encrypted.Length);
            }

            if (stream.DataAvailable)
            {
                // Recebe mensagem
                var buffer = new byte[1024];
                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                // Exibe a mensagem criptografada (em Base64 para legibilidade)
                Console.WriteLine($"[INTERCEPTADO] Mensagem criptografada (Base64): {Convert.ToBase64String(buffer[..bytesRead])}");


                var decrypted = Decrypt(buffer[..bytesRead], aes, hmacKey);
                Console.WriteLine($"Outro: {decrypted}");
            }

            Thread.Sleep(100);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro: {ex.Message}");
    }
}

byte[] Encrypt(string message, Aes aes, byte[] hmacKey)
{
    // Criptografa
    using var encryptor = aes.CreateEncryptor();
    using var ms = new MemoryStream();
    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
    using (var writer = new StreamWriter(cs))
    {
        writer.Write(message);
    }

    var encrypted = ms.ToArray();

    // Calcula HMAC
    using var hmac = new HMACSHA256(hmacKey);
    var hmacDigest = hmac.ComputeHash(encrypted.Concat(aes.IV).ToArray());

    // Junta tudo
    return hmacDigest.Concat(encrypted).Concat(aes.IV).ToArray();
}

string Decrypt(byte[] data, Aes aes, byte[] hmacKey)
{
    // Separa partes
    var hmacReceived = data[..32];
    var encrypted = data[32..^16];
    var iv = data[^16..];

    // Verifica integridade
    using var hmac = new HMACSHA256(hmacKey);
    var hmacComputed = hmac.ComputeHash(encrypted.Concat(iv).ToArray());

    if (!hmacReceived.SequenceEqual(hmacComputed))
        throw new Exception("Mensagem corrompida!");

    // Decripta
    aes.IV = iv;
    using var decryptor = aes.CreateDecryptor();
    using var ms = new MemoryStream(encrypted);
    using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
    using var reader = new StreamReader(cs);

    return reader.ReadToEnd();
}

byte[] ReadBytes(NetworkStream stream, int count)
{
    var buffer = new byte[count];
    var read = 0;
    while (read < count)
        read += stream.Read(buffer, read, count - read);
    return buffer;
}