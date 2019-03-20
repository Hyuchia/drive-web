import copy from "copy-to-clipboard";
const CryptoJS = require('crypto-js');
const Storj = require('storj');

function copyToClipboard(text) {
  copy(text);
}

// Method to hash password. If salt is passed, use it, in other case use crypto lib for generate salt
function passToHash(passObject) {
  try {
    const salt = passObject.salt ? CryptoJS.enc.Hex.parse(passObject.salt) : CryptoJS.lib.WordArray.random(128/8);
    const hash = CryptoJS.PBKDF2(passObject.password, salt, { keySize: 256/32, iterations: 10000 });
    const hashedObjetc = {
      salt : salt.toString(),
      hash : hash.toString()
    }
    return hashedObjetc;
  } catch (error) {
    throw new Error(error);
  }
}

// AES Plain text encryption method
function encryptText(textToEncrypt) {
  try {
    const bytes = CryptoJS.AES.encrypt(textToEncrypt, process.env.REACT_APP_CRYPTO_SECRET).toString();
    const text64 = CryptoJS.enc.Base64.parse(bytes);
    return text64.toString(CryptoJS.enc.Hex);
  } catch (error) {
    throw new Error(error);
  }
}

// AES Plain text decryption method
function decryptText(encryptedText) {
  try {
    const reb = CryptoJS.enc.Hex.parse(encryptedText);
    const bytes = CryptoJS.AES.decrypt(reb.toString(CryptoJS.enc.Base64), process.env.REACT_APP_CRYPTO_SECRET);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    throw new Error(error);
  }
}

// AES Plain text encryption method with enc. key
function encryptTextWithKey(textToEncrypt, keyToEncrypt) {
  try {
    const bytes = CryptoJS.AES.encrypt(textToEncrypt, keyToEncrypt).toString();
    const text64 = CryptoJS.enc.Base64.parse(bytes);
    return text64.toString(CryptoJS.enc.Hex);
  } catch (error) {
    throw new Error(error);
  }
}

// AES Plain text decryption method with enc. key
function decryptTextWithKey(encryptedText, keyToDecrypt) {
  try {
    const reb = CryptoJS.enc.Hex.parse(encryptedText);
    const bytes = CryptoJS.AES.decrypt(reb.toString(CryptoJS.enc.Base64), keyToDecrypt);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    throw new Error(error);
  }
}

// Upload files to node network
function uploadFile (user, folder, file) {
	return new Promise(async (resolve, reject) => {
		try {
			// Check mnemonic
      if (!user.mnemonic) throw new Error('Your mnemonic is invalid')
      const fileName = file.name;
			console.log('Starting file upload: ' + fileName);
			console.log('Folder to upload file: ' + folder.name)
			// Get file name without extension
			const extSeparatorPos = fileName.lastIndexOf('.')
			const fileNameNoExt = fileName.slice(0, extSeparatorPos)
			console.log('Encrypting file name')
			const encryptedFileName = encryptText(fileNameNoExt)

			// CHECK IF EXISTS FILE WITH SAME NAME IN THE UPLOAD FOLDER

			const fileExt = fileName.slice(extSeparatorPos + 1);
			const encryptedFileNameWithExt = encryptedFileName + '.' + fileExt;
			console.log('Uploading file to network');

      storeFile(user, folder.bucket, file, encryptedFileNameWithExt)
      .then(async (addedFile) => {
        // CREATE REGS ON DB TO NEW FILE
        // AND ADD THIS FILE TO FOLDER IN DB

        // END METHOD RETURNING FILE CREATED IN DB
        resolve(addedFile)
      }).catch((err) => {
        reject(err.message)
      });
			
		} catch (error) {
			console.error(error.message);
		}
	})
}

// Storj functions

function getEnvironment(email, password, mnemonic) {
  try {
    let opts = {
      bridge: process.env.REACT_APP_STORJ_BRIDGE,
      basicAuth: { email, password },
      encryptionKey: mnemonic
    }
    return new Storj(opts);
  } catch (error) {
    console.error('(getEnvironment) ' + error);
    return null;
  }
}

const storeFile = (user, bucketId, file, fileName) => {
  return new Promise((resolve, reject) => {
    try {
      const storj = getEnvironment(user.email, user.userId, user.mnemonic)
      
      storj.on('ready', () => {
        let fileObj = storj.createFile(bucketId, fileName, file);

        fileObj.on('ready', (res) => {
          console.log('File processed');
          console.log(res);
        });
        fileObj.on('done', (res) => {
          console.log('Upload finished')
          console.log(res);
          resolve(res);
        });
        fileObj.on('error', (error) => {
          console.error(error);
          reject(error);
        })
      })
    } catch(error){
      reject(error);
    }
  });
}

export {
  copyToClipboard,
  passToHash,
  encryptText,
  decryptText,
  encryptTextWithKey,
  decryptTextWithKey,
  uploadFile
}
