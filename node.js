const forge = require("node-forge");

function generateRSAKeyPair() {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keyPair) => {
      if (err) {
        reject(err);
      } else {
        const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
        const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);

        resolve({
          privateKeyPem: privateKeyPem,
          publicKeyPem: publicKeyPem,
          keyPair: keyPair,
        });
      }
    });
  });
}

function encryptMessage(publicKeyPem, message) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

  const aesKey = forge.random.getBytesSync(32);
  const iv = forge.random.getBytesSync(16);

  const cipher = forge.cipher.createCipher("AES-GCM", aesKey);
  cipher.start({ iv: iv });
  cipher.update(forge.util.createBuffer(message, "utf8"));
  cipher.finish();

  const encrypted = cipher.output.getBytes();
  const tag = cipher.mode.tag.getBytes();

  const encryptedKey = publicKey.encrypt(aesKey);

  return {
    encryptedKey: forge.util.encode64(encryptedKey),
    iv: forge.util.encode64(iv),
    encryptedData: forge.util.encode64(encrypted),
    tag: forge.util.encode64(tag),
  };
}

function decryptMessage(privateKeyPem, encryptedPackage) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  const encryptedKey = forge.util.decode64(encryptedPackage.encryptedKey);
  const aesKey = privateKey.decrypt(encryptedKey);

  const iv = forge.util.decode64(encryptedPackage.iv);
  const tag = forge.util.decode64(encryptedPackage.tag);
  const encryptedData = forge.util.decode64(encryptedPackage.encryptedData);

  const decipher = forge.cipher.createDecipher("AES-GCM", aesKey);
  decipher.start({
    iv: iv,
    tag: forge.util.createBuffer(tag),
  });
  decipher.update(forge.util.createBuffer(encryptedData));
  const result = decipher.finish();

  if (result) {
    return decipher.output.toString();
  } else {
    throw new Error("Decryption failed - message has been tampered with");
  }
}

(async () => {
  const { privateKeyPem, publicKeyPem } = await generateRSAKeyPair();
  const encryptedPackage = encryptMessage(publicKeyPem, "Hello World!");
  const decryptPackage = decryptMessage(privateKeyPem, encryptedPackage);
})();
