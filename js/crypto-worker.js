const MAGIC_HEADER = "NOURCRYPT";
const CHUNK_SIZE = 8 * 1024 * 1024;
const PBKDF2_ITERATIONS = 600000;

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(bytes);
}

// Safe binary-to-base64 that avoids stack overflow from spread operator
function uint8ToBase64(uint8) {
  const CHUNK = 8192;
  let binary = '';
  for (let i = 0; i < uint8.length; i += CHUNK) {
    const slice = uint8.subarray(i, Math.min(i + CHUNK, uint8.length));
    binary += String.fromCharCode.apply(null, slice);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Sanitize filenames to prevent path traversal or invalid characters
function sanitizeFileName(name) {
  // Strip path separators and parent directory references
  return name.replace(/[\\\/]/g, '_').replace(/\.\./g, '_').replace(/^\s+|\s+$/g, '');
}

async function deriveKey(password, salt) {
  const passwordBytes = strToBytes(password);
  const baseKey = await self.crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return await self.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function generateIV(length = 12) {
  return self.crypto.getRandomValues(new Uint8Array(length));
}

async function handleEncryptFile(file, password, customOutputName) {
  const startTime = performance.now();
  const totalSize = file.size;

  if (totalSize === 0) {
    throw new Error("Cannot encrypt an empty (0 bytes) file.");
  }

  const salt = self.crypto.getRandomValues(new Uint8Array(16));
  const masterIV = generateIV(12);

  const key = await deriveKey(password, salt);

  const metadata = {
    name: file.name,
    size: file.size,
    type: file.type || "application/octet-stream",
    timestamp: Date.now()
  };
  const metadataBytes = strToBytes(JSON.stringify(metadata));
  const encryptedMetadataBuf = await self.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: masterIV },
    key,
    metadataBytes
  );
  const encryptedMetadata = new Uint8Array(encryptedMetadataBuf);

 if (encryptedMetadata.length > 65535) {
    throw new Error("Encrypted metadata exceeds maximum supported size (65,535 bytes). Try a shorter filename.");
  }
  
  const magicBytes = strToBytes(MAGIC_HEADER);
  const versionBytes = new Uint8Array([0x00, 0x01]);
  const metaLenBytes = new Uint8Array(2);
  new DataView(metaLenBytes.buffer).setUint16(0, encryptedMetadata.length, false);

  const binaryParts = [
    magicBytes,
    versionBytes,
    salt,
    masterIV,
    metaLenBytes,
    encryptedMetadata
  ];

  let offset = 0;
  let chunkIndex = 0;
  let processedBytes = 0;

  while (offset < totalSize) {
    const chunkEnd = Math.min(offset + CHUNK_SIZE, totalSize);
    const blobSlice = file.slice(offset, chunkEnd);
    const chunkBuffer = await blobSlice.arrayBuffer();

    const chunkIV = generateIV(12);

    const encryptedChunkBuf = await self.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: chunkIV },
      key,
      chunkBuffer
    );
    const encryptedChunk = new Uint8Array(encryptedChunkBuf);

    const chunkLenBytes = new Uint8Array(4);
    new DataView(chunkLenBytes.buffer).setUint32(0, encryptedChunk.length, false);

    binaryParts.push(chunkIV);
    binaryParts.push(chunkLenBytes);
    binaryParts.push(encryptedChunk);

    processedBytes += (chunkEnd - offset);
    offset = chunkEnd;
    chunkIndex++;

    const elapsedSec = (performance.now() - startTime) / 1000;
    const speedBps = elapsedSec > 0 ? processedBytes / elapsedSec : 0;
    const remainingBytes = totalSize - processedBytes;
    const etaSec = speedBps > 0 ? Math.ceil(remainingBytes / speedBps) : 0;

    self.postMessage({
      type: "PROGRESS",
      processedBytes,
      totalBytes: totalSize,
      percent: totalSize > 0 ? Math.min(100, Math.round((processedBytes / totalSize) * 100)) : 100,
      speedMBps: (speedBps / (1024 * 1024)).toFixed(2),
      etaSec
    });

    if (offset >= totalSize) break;
  }

  const resultBlob = new Blob(binaryParts, { type: "application/nourcrypt" });
  
  let outputFileName = "";
  if (customOutputName && customOutputName.trim()) {
    let name = sanitizeFileName(customOutputName.trim());
    if (!name) name = 'encrypted';
    outputFileName = name.endsWith(".nour") ? name : `${name}.nour`;
  } else {
    const randHash = Array.from(self.crypto.getRandomValues(new Uint8Array(4)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    outputFileName = `encrypted_${randHash}.nour`;
  }

  self.postMessage({
    type: "SUCCESS",
    blob: resultBlob,
    fileName: outputFileName,
    metadata
  });
}

async function handleDecryptFile(file, password, customOutputName) {
  const startTime = performance.now();
  const totalSize = file.size;

  if (totalSize < 41) {
    throw new Error("Invalid file: File is too small to be a NourCrypt encrypted package.");
  }

  const headerSlice = file.slice(0, Math.min(4096, totalSize));
  const headerBuf = await headerSlice.arrayBuffer();
  const view = new DataView(headerBuf);

  const magic = bytesToStr(new Uint8Array(headerBuf, 0, 9));
  if (magic !== MAGIC_HEADER) {
    throw new Error("Invalid format: Not a recognized NourCrypt (.nour) file.");
  }

  const salt = new Uint8Array(headerBuf, 11, 16);
  const masterIV = new Uint8Array(headerBuf, 27, 12);
  const metaLen = view.getUint16(39, false);

  const headerTotalOffset = 41 + metaLen;
  if (totalSize < headerTotalOffset) {
    throw new Error("Corrupted file header metadata.");
  }

  const key = await deriveKey(password, salt);

  const encryptedMetaBuf = await file.slice(41, 41 + metaLen).arrayBuffer();
  let metadata;
  try {
    const decryptedMetaBuf = await self.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: masterIV },
      key,
      encryptedMetaBuf
    );
    metadata = JSON.parse(bytesToStr(new Uint8Array(decryptedMetaBuf)));
  } catch (err) {
    throw new Error("Incorrect password or corrupted file header.");
  }

  let offset = headerTotalOffset;
  const decryptedParts = [];
  let processedBytes = 0;
  const payloadSize = totalSize - headerTotalOffset;

  while (offset < totalSize) {
    const chunkHeadSlice = file.slice(offset, offset + 16);
    const chunkHeadBuf = await chunkHeadSlice.arrayBuffer();
    if (chunkHeadBuf.byteLength < 16) break;

    const chunkIV = new Uint8Array(chunkHeadBuf, 0, 12);
    const chunkLen = new DataView(chunkHeadBuf).getUint32(12, false);

    offset += 16;
    const chunkSlice = file.slice(offset, offset + chunkLen);
    const chunkCipherBuf = await chunkSlice.arrayBuffer();

    let decryptedChunkBuf;
    try {
      decryptedChunkBuf = await self.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: chunkIV },
        key,
        chunkCipherBuf
      );
    } catch (err) {
      throw new Error(`Decryption failed at byte ${offset}. Password may be incorrect or data altered.`);
    }

    decryptedParts.push(new Uint8Array(decryptedChunkBuf));
    offset += chunkLen;
    processedBytes += (16 + chunkLen);

    const elapsedSec = (performance.now() - startTime) / 1000;
    const speedBps = elapsedSec > 0 ? processedBytes / elapsedSec : 0;
    const remainingBytes = payloadSize - processedBytes;
    const etaSec = speedBps > 0 ? Math.max(0, Math.ceil(remainingBytes / speedBps)) : 0;

    self.postMessage({
      type: "PROGRESS",
      processedBytes,
      totalBytes: payloadSize,
      percent: payloadSize > 0 ? Math.min(100, Math.round((processedBytes / payloadSize) * 100)) : 100,
      speedMBps: (speedBps / (1024 * 1024)).toFixed(2),
      etaSec
    });
  }

  const resultBlob = new Blob(decryptedParts, { type: metadata.type || "application/octet-stream" });
  
  let finalDecryptedName = metadata.name || "decrypted_file";
  if (customOutputName && customOutputName.trim()) {
    finalDecryptedName = sanitizeFileName(customOutputName.trim()) || "decrypted_file";
  }

  self.postMessage({
    type: "SUCCESS",
    blob: resultBlob,
    fileName: finalDecryptedName,
    metadata
  });
}

async function handleEncryptText(text, password) {
  const salt = self.crypto.getRandomValues(new Uint8Array(16));
  const iv = generateIV(12);
  const key = await deriveKey(password, salt);

  const textBytes = strToBytes(text);
  const ciphertextBuf = await self.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    textBytes
  );

  const saltB64 = uint8ToBase64(salt);
  const ivB64 = uint8ToBase64(iv);
  const cipherB64 = uint8ToBase64(new Uint8Array(ciphertextBuf));

  const result = `NOUR1:${saltB64}:${ivB64}:${cipherB64}`;
  self.postMessage({ type: "TEXT_SUCCESS", result });
}

async function handleDecryptText(formattedText, password) {
  const parts = formattedText.trim().split(":");
  if (parts.length !== 4 || parts[0] !== "NOUR1") {
    throw new Error("Invalid encrypted text format. Must start with NOUR1:");
  }

  let salt, iv, cipherBytes;
  try {
    salt = base64ToUint8(parts[1]);
    iv = base64ToUint8(parts[2]);
    cipherBytes = base64ToUint8(parts[3]);
  } catch (e) {
    throw new Error("Invalid base64 encoding in encrypted text.");
  }

  if (salt.length !== 16 || iv.length !== 12) {
    throw new Error("Corrupted text cipher parameters (invalid salt or IV size).");
  }

  const key = await deriveKey(password, salt);
  let decryptedBuf;
  try {
    decryptedBuf = await self.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBytes
    );
  } catch (e) {
    throw new Error("Text decryption failed. Incorrect password or tampered text.");
  }

  const result = bytesToStr(new Uint8Array(decryptedBuf));
  self.postMessage({ type: "TEXT_SUCCESS", result });
}

self.onmessage = async function(e) {
  const { action, file, text, password, customOutputName } = e.data;
  try {
    if (action === "ENCRYPT_FILE") {
      await handleEncryptFile(file, password, customOutputName);
    } else if (action === "DECRYPT_FILE") {
      await handleDecryptFile(file, password, customOutputName);
    } else if (action === "ENCRYPT_TEXT") {
      await handleEncryptText(text, password);
    } else if (action === "DECRYPT_TEXT") {
      await handleDecryptText(text, password);
    }
  } catch (err) {
    self.postMessage({
      type: "ERROR",
      message: err.message || "An unexpected cryptographic error occurred."
    });
  }
};
