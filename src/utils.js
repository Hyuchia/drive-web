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
			const fileExt = fileName.slice(extSeparatorPos + 1);
			const encryptedFileNameWithExt = encryptedFileName + '.' + fileExt;
			console.log('Uploading file to network');

      // Call node network method to store file
      storeFile(user, folder.bucket, file, encryptedFileNameWithExt)
      .then(async (addedFile) => {
        const file = {
          name: encryptedFileName,
          type: fileExt,
          bucketId: addedFile.bucket,
          folder_id: folder.id,
          size: addedFile.size
        }

        // Create file in xCloud db and add it to folder
        fetch('/api/storage/file', {
          method: "post",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("xToken")}`,
            "content-type": "application/json; charset=utf-8",
            "internxt-mnemonic": localStorage.getItem("xMnemonic")
          },
          body: JSON.stringify({ file })
        }).then(response => response.json())
          .then(data => {
            resolve(data)
          });
      }).catch((err) => {
        reject(err.message)
      });
		} catch (error) {
      reject(error.message)
		}
	})
}

// Download file from node network
// result is object containing:
//  blob: blob object with data from file
//  fileName: decrypted file name
function downloadFile (user, folderBucket, fileId) {
  return new Promise((resolve, reject) => {
    // Check mnemonic
    if (!user.mnemonic) throw new Error('Your mnemonic is invalid')

    getFile(user, folderBucket, fileId)
    .then((res) => {
      resolve(res);
    }).catch((err) => {
      reject(err.message);
    })
  })
}

// Storj functions

function getEnvironment(email, password, mnemonic) {
  try {
    let opts = {
      bridge: process.env.REACT_APP_STORJ_BRIDGE,
      basicAuth: { email, password },
      encryptionKey: mnemonic,
      protocol: 'https',
      logger: console //ONLY FOR TESTING
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

        fileObj.on('ready', () => {
          console.log('File processed');
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

const getFile = (user, bucketId, fileId) => {
  return new Promise((resolve, reject) => {
    try {
      var fileName;
      const storj = getEnvironment(user.email, user.userId, user.mnemonic);
      var fileObj = storj.getFile(bucketId, fileId);

      fileObj.on('downloaded', () => {
        console.log('Finished downloading file!')
      });
      fileObj.on('done', () => {
        console.log('file finished decrypting')
        // Decrypt filename
        const fileNameEnc = fileObj.name.split('.')[0];
        const fileNameDecrypt = decryptText(fileNameEnc);
        const fileExt = fileObj.name.split('.')[1];
        fileName = `${fileNameDecrypt}.${fileExt}`;
        
        fileObj.getBlob(function (err, blob) {
          if (err) throw err
          resolve({blob, fileName});
        })
      })
      fileObj.on('error', (error) => {
        console.error(error);
        reject(error);
      });
    } catch (error) {
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
  uploadFile,
  downloadFile
}
