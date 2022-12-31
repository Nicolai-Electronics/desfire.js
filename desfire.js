"use strict";

const crypto = require("crypto");

function writeUint24LE(buffer, value, position = 0) {
    let tempBuffer = Buffer.alloc(4);
    tempBuffer.writeUint32LE(value);
    tempBuffer.copy(buffer, position, 0, 3);
}

class DesfireBase {
    constructor() {
        this.constants = {
            NotAuthenticated: 255,
            MaxFrameSize: 60, // The maximum total length of a packet that is transfered to / from the card

            commands: {
                // Security related commands
                AuthenticateLegacy: 0x0A,
                ChangeKeySettings: 0x54,
                GetKeySettings: 0x45,
                ChangeKey: 0xC4,
                GetKeyVersion: 0x64,

                // PICC level commands
                CreateApplication: 0xCA,
                DeleteApplication: 0xDA,
                GetApplicationIdentifiers: 0x6A,
                SelectApplication: 0x5A,
                FormatPicc: 0xFC,
                GetVersion: 0x60,

                // Application level commands
                GetFileIdentifiers: 0x6F,
                GetFileSettings: 0xF5,
                ChangeFileSettings: 0x5F,
                CreateStandardDataFile: 0xCD,
                CreateBackupDataFile: 0xCB,
                CreateValueFile: 0xCC,
                CreateLinearRecordFile: 0xC1,
                CreateCyclicRecordFile: 0xC0,
                DeleteFile: 0xDF,

                // Data manipulation commands
                ReadData: 0xBD,
                WriteData: 0x3D,
                GetValue: 0x6C,
                Credit: 0x0C,
                Debit: 0xDC,
                LimitedCredit: 0x1C,
                WriteRecord: 0x3B,
                ReadRecords: 0xBB,
                ClearRecordFile: 0xEB,
                CommitTransaction: 0xC7,
                AbortTransaction: 0xA7,

                // Other
                AdditionalFrame: 0xAF, // data did not fit into a frame, another frame will follow

                // Desfire EV1 instructions
                Ev1AuthenticateIso: 0x1A,
                Ev1AuthenticateAes: 0xAA,
                Ev1FreeMem: 0x6E,
                Ev1GetDfNames: 0x6D,
                Ev1GetCardUid: 0x51,
                Ev1GetIsoFileIdentifiers: 0x61,
                Ev1SetConfiguration: 0x5C,

                // ISO7816 instructions
                ISO7816ExternalAuthenticate: 0x82,
                ISO7816InternalAuthenticate: 0x88,
                ISO7816AppendRecord: 0xE2,
                ISO7816GetChallenge: 0x84,
                ISO7816ReadRecords: 0xB2,
                ISO7816SelectFile: 0xA4,
                ISO7816ReadBinary: 0xB0,
                ISO7816UpdateBinary: 0xD6
            },
            
            status: {
                success: 0x00,
                noChanges: 0x0C,
                outOfMemory: 0x0E,
                illegalCommand: 0x1C,
                integrityError: 0x1E,
                keyDoesNotExist: 0x40,
                wrongCommandLen: 0x7E,
                permissionDenied: 0x9D,
                incorrectParam: 0x9E,
                appNotFound: 0xA0,
                appIntegrityError: 0xA1,
                authentError: 0xAE,
                moreFrames: 0xAF, // data did not fit into a frame, another frame will follow
                limitExceeded: 0xBE,
                cardIntegrityError: 0xC1,
                commandAborted: 0xCA,
                cardDisabled: 0xCD,
                invalidApp: 0xCE,
                duplicateAidFiles: 0xDE,
                eepromError: 0xEE,
                fileNotFound: 0xF0,
                fileIntegrityError: 0xF1
            },

            keySettings: {
                // Bits 0-3
                allowChangeMk: 0x01, // If this bit is set, the MK can be changed, otherwise it is frozen.
                listingWithoutMk: 0x02, // Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication, App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
                createDeleteWithoutMk: 0x04, // Picc key: If this bit is set, CreateApplication does not require MK authentication, App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
                configurationChangeable: 0x08, // If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
                
                // Bits 4-7 (not used for the PICC master key)
                changeKeyWithMk: 0x00, // A key change requires MK authentication
                changeKeyWithKey1: 0x10, // A key change requires authentication with key 1
                changeKeyWithKey2: 0x20, // A key change requires authentication with key 2
                changeKeyWithKey3: 0x30, // A key change requires authentication with key 3
                changeKeyWithKey4: 0x40, // A key change requires authentication with key 4 
                changeKeyWithKey5: 0x50, // A key change requires authentication with key 5
                changeKeyWithKey6: 0x60, // A key change requires authentication with key 6
                changeKeyWithKey7: 0x70, // A key change requires authentication with key 7
                changeKeyWithKey8: 0x80, // A key change requires authentication with key 8
                changeKeyWithKey9: 0x90, // A key change requires authentication with key 9
                changeKeyWithKeyA: 0xA0, // A key change requires authentication with key 10
                changeKeyWithKeyB: 0xB0, // A key change requires authentication with key 11
                changeKeyWithKeyC: 0xC0, // A key change requires authentication with key 12
                changeKeyWithKeyD: 0xD0, // A key change requires authentication with key 13
                changeKeyWithTargetedKey: 0xE0, // A key change requires authentication with the same key that is to be changed
                changeKeyFrozen: 0xF0, // All keys are frozen

                factoryDefault: 0x0F
            },
            
            keyType: {
                DES: 0x00,
                TDES: 0x40,
                AES: 0x80
            },

            fileType: {
                standard: 0x00,
                CreateBackupDataFile: 0x01,
                value: 0x02,
                linear: 0x03,
                cyclic: 0x04
            },

            communicationSettings: {
                plain: 0,
                cmac: 1,
                encrypted: 3
            },

            accessRights: {
                key0: 0x0,
                key1: 0x1,
                key2: 0x2,
                key3: 0x3,
                key4: 0x4,
                key5: 0x5,
                key6: 0x6,
                key7: 0x7,
                key8: 0x8,
                key9: 0x9,
                keyA: 0xA,
                keyB: 0xB,
                keyC: 0xC,
                keyD: 0xD,
                free: 0xE,
                deny: 0xF
            }
        };
    }
};

class DesfireKey extends DesfireBase {
    constructor(keyId, key) {
        super();
        if (Array.isArray(key)) {
            key = Buffer.from(key);
        }
        if (!Buffer.isBuffer(key)) {
            throw new Error("expected key to be a buffer or array");
        }
        this.authenticationKey = key;
        this.authenticationkeyIdentifier = keyId;

        this.keySize = key.length;
        this.blockSize = 8;

        this.random_a = null;
        this.random_b = null;

        this.sessionKey = null;
        this.sessionIv = null;

        this.cmac1 = null;
        this.cmac2 = null;
    }
    
    rotateLeft(buffer) {
        return Buffer.concat([buffer.slice(1, buffer.length), buffer.slice(0, 1)]);
    }
    
    rotateRight(buffer) {
        return Buffer.concat([buffer.slice(buffer.length - 1, buffer.length), buffer.slice(0, buffer.length - 1)]);
    }
    
    bitShiftLeft(buffer) {
        for (let index = 0; index < buffer.length - 1; index++) {
            buffer[index] = (buffer[index] << 1) | (buffer[index + 1] >> 7);
        }
        buffer[buffer.length - 1] = buffer[buffer.length - 1] << 1;
    }
    
    clearIv(session) {
        if (session) {
            this.sessionIv = Buffer.alloc(this.blockSize).fill(0);
        } else {
            this.authenticationIv = Buffer.alloc(this.blockSize).fill(0);
        }
    }

    generateCmacSubKeys() {
        this.clearIv(true);
        let R = (this.blockSize == 8) ? 0x1B : 0x87;
        let data = Buffer.alloc(this.blockSize).fill(0);
        this.cmac1 = Buffer.alloc(this.blockSize);
        this.cmac2 = Buffer.alloc(this.blockSize);

        data = this.encrypt(data, true);

        data.copy(this.cmac1);
        this.bitShiftLeft(this.cmac1);
        if (data[0] & 0x80) {
            this.cmac1[this.cmac1.length - 1] ^= R;
        }

        this.cmac1.copy(this.cmac2);
        this.bitShiftLeft(this.cmac2);
        if (this.cmac1[0] & 0x80) {
            this.cmac2[this.cmac2.length - 1] ^= R;
        }

        this.clearIv(true);
    }

    decrypt(data, session) {
        throw new Error("not implemented");
    }
    
    encrypt(data, session) {
        throw new Error("not implemented");
    }
    
    async authenticate() {
        throw new Error("not implemented");
    }
}

class DesfireKeyDes extends DesfireKey {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 8;
    }
    
    decrypt(data, session) {
        const decipher = crypto.createDecipheriv("DES-EDE-CBC", session ? this.sessionKey : this.authenticationKey, Buffer.alloc(8).fill(0));
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    encrypt(data, session) {
        const decipher = crypto.createCipheriv("DES-EDE-CBC", session ? this.sessionKey : this.authenticationKey, Buffer.alloc(8).fill(0));
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    async authenticate(card) {
        this.clearIv(false);
        let [data, returnCode] = await card.communicate(this.constants.commands.AuthenticateLegacy, [this.authenticationkeyIdentifier], null, false, false, false, false);
        if (returnCode !== this.constants.status.moreFrames) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted, false);
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]), false);
        [data, returnCode] = await card.communicate(this.constants.commands.AdditionalFrame, ciphertext, null, false, false, false, false);
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to set up random_a");
        }
        const random_a2_encrypted_rotated = data;
        const random_a2_rotated = this.decrypt(random_a2_encrypted_rotated, false); // decrypt to get rotated value of random_a2
        const random_a2 =this.rotateRight(random_a2_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4), this.random_a.slice(0,4), this.random_b.slice(0,4)]);
        this.clearIv(true);
        this.generateCmacSubKeys();
    }
}

class DesfireKeyAes extends DesfireKey {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 16;
    }

    decrypt(data, session) {
        //if (session) console.log("AES D");
        const decipher = crypto.createDecipheriv("AES-128-CBC", session ? this.sessionKey : this.authenticationKey, session ? this.sessionIv : this.authenticationIv);
        decipher.setAutoPadding(false);
        let result = Buffer.concat([decipher.update(data), decipher.final()]);
        if (session) {
            this.sessionIv = data.slice(-1 * this.blockSize);
        } else {
            this.authenticationIv = data.slice(-1 * this.blockSize);
        }
        return result;
    }
    
    encrypt(data, session) {
        //if (session) console.log("AES E", this.sessionIv);
        const cipher = crypto.createCipheriv("AES-128-CBC", session ? this.sessionKey : this.authenticationKey, session ? this.sessionIv : this.authenticationIv);
        cipher.setAutoPadding(false);
        let result = Buffer.concat([cipher.update(data), cipher.final()]);
        if (session) {
            this.sessionIv = result.slice(-1 * this.blockSize);
        } else {
            this.authenticationIv = result.slice(-1 * this.blockSize);
        }
        return result;
    }
    
    async authenticate(card) {
        this.clearIv(false);
        let [data, returnCode] = await card.communicate(this.constants.commands.Ev1AuthenticateAes, [this.authenticationkeyIdentifier], null, false, false, false, false);
        if (returnCode !== this.constants.status.moreFrames) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted, false);
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]), false);
        [data, returnCode] = await card.communicate(this.constants.commands.AdditionalFrame, ciphertext, null, false, false, false, false);
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to set up random_a");
        }
        const random_a_encrypted_rotated = data; // encrypted random a from reader
        const random_a_rotated = this.decrypt(random_a_encrypted_rotated, false); // decrypt to get rotated value of random_a2
        const random_a2 = this.rotateRight(random_a_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4), this.random_a.slice(12, 16), this.random_b.slice(12, 16)]);
        this.clearIv(true);
        this.generateCmacSubKeys();
    }
}

class DesfireCardVersion extends DesfireBase {
    constructor(buffer) {
        super();
        if (buffer.length != 28) {
            throw new Error("Expected exactly 28 bytes");
        }
        this.vendorId             = buffer.readUint8(0);
        this.hardwareType         = buffer.readUint8(1);
        this.hardwareSubType      = buffer.readUint8(2);
        this.hardwareMajorVersion = buffer.readUint8(3);
        this.HardwareMinorVersion = buffer.readUint8(4);
        this.hardwareStorageSize  = buffer.readUint8(5);
        this.hardwareProtocol     = buffer.readUint8(6);
        this.softwareVendorId     = buffer.readUint8(7);
        this.softwareType         = buffer.readUint8(8);
        this.softwareSubType      = buffer.readUint8(9);
        this.softwareMajorVersion = buffer.readUint8(10);
        this.softwareMinorVersion = buffer.readUint8(11);
        this.softwareStorageSize  = buffer.readUint8(12);
        this.softwareProtocol     = buffer.readUint8(13);
        this.uid                  = buffer.slice(14,21).toJSON().data;;
        this.batchNumber          = buffer.slice(21,26).toJSON().data;;
        this.productionWeek       = buffer.readUint8(26);
        this.productionYear       = buffer.readUint8(27);
    }
    
    print() {
        console.log("Hardware version: " + this.hardwareMajorVersion + "." + this.HardwareMinorVersion);
        console.log("Software version: " + this.softwareMajorVersion + "." + this.softwareMinorVersion);
        console.log("Storage capacity: " + (1 << (this.hardwareStorageSize / 2)));
        console.log("Production date:  week " + this.productionWeek.toString(16) + " of 20" + ((this.productionYear < 0x10) ? "0" : "") + this.productionYear.toString(16));
        let batchNumberStringArray = [];
        for (let index = 0; index < this.batchNumber.length; index++) {
            batchNumberStringArray.push(((this.batchNumber[index] < 0x10) ? "0" : "") + this.batchNumber[index].toString(16));
        }
        console.log("Batch number:     " + batchNumberStringArray.join(""));
        let uidStringArray = [];
        for (let index = 0; index < this.uid.length; index++) {
            uidStringArray.push(((this.uid[index] < 0x10) ? "0" : "") + this.uid[index].toString(16));
        }
        console.log("Unique ID:        " + uidStringArray.join(""));
        
    }
}

class DesfireKeySettings {
    constructor(buffer = Buffer.from([0x0F, 0x00])) {
        if (buffer.length < 2) {
            buffer = buffer.concat(Buffer.from([0x00]));
        }
        let settings = buffer.readUint8(0);
        this.allowChangeMk              = Boolean(settings & 0x01);
        this.allowListingWithoutMk      = Boolean(settings & 0x02);
        this.allowCreateDeleteWithoutMk = Boolean(settings & 0x04);
        this.allowChangeConfiguration   = Boolean(settings & 0x08);
        this.allowChangeWithKey         = (settings & 0xF0) >> 4; // 0x0 is master key, 0xE is target key, 0xF is frozen
        this.keyCount = buffer.readUint8(1) & 0x0F;
        let _keyType = buffer.readUint8(1) & 0xF0;
        this.keyType = "invalid";
        if (_keyType === 0x00) {
            this.keyType = "des";
        } else if (_keyType == 0x40) {
            this.keyType = "3des";
        } else if (_keyType == 0x80) {
            this.keyType = "aes";
        }
    }
    
    getBuffer() {
        let _keyType = null;
        if (this.keyType === "des") {
            _keyType = 0x00;
        } else if (this.keyType === "3des") {
            _keyType = 0x40;
        } else if (this.keyType === "aes") {
            _keyType = 0x80;
        } else {
            throw new Error("key type invalid");
        }
        let settings = (this.allowChangeWithKey << 4) | (this.allowChangeMk ? 1 : 0) | (this.allowListingWithoutMk ? 2 : 0) | (this.allowCreateDeleteWithoutMk ? 4 : 0) | (this.allowChangeConfiguration ? 8 : 0);
        return Buffer.from([settings, this.keyCount + _keyType]);
    }

    getSettings() {
        return this.getBuffer()[0];
    }
}

class DesfireCard extends DesfireBase {
    constructor(reader, card) {
        super();
        this._reader = reader;
        this._card = card;

        this.default_des_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_3des_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_aes_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        this.key = null;
        this.appId = 0x000000;
    }

    // Helper functions

    getKeyByValue(object, value) {
        return Object.keys(object).find(key => object[key] === value);
    }

    async communicate(cmd, data = [], encryptData = null, calculateTxCmac = false, checkRxCmac = false, decryptRxData = false, handleAdditionalFrames = true, extraEncryptData = null) {
        if (((encryptData !== null) || calculateTxCmac || checkRxCmac || decryptRxData) && (this.key === null)) {
            throw Error("Not authenticated");
        }

        if (calculateTxCmac) {
            let txData = Buffer.from([cmd, ...data]);
            await this.calculateCmac(txData);
        }

        let plainData = Buffer.from(data);

        let packet = this.wrap(cmd, plainData);

        if (encryptData !== null) {
            encryptData = Buffer.from(encryptData);
            let crcSize = (this.key instanceof DesfireKeyAes) ? 4 : 2;
            let crcInput = Buffer.concat([Buffer.from([cmd]), Buffer.from(data), Buffer.from(encryptData)]);
            let crc = (this.key instanceof DesfireKeyAes) ? this.crc32(crcInput) : this.crc16(Buffer.from(crcInput));
            let buffer = Buffer.alloc(encryptData.length + crcSize);
            encryptData.copy(buffer);
            buffer.writeUInt32LE(crc, encryptData.length);
            if (extraEncryptData !== null) {
                buffer = Buffer.concat([buffer, extraEncryptData]);
            }
            let encryptedData = await this.padAndEncrypt(buffer);
            let combinedData = Buffer.alloc(plainData.length + encryptedData.length);
            plainData.copy(combinedData);
            encryptedData.copy(combinedData, plainData.length);
            packet = this.wrap(cmd, combinedData);
        }

        //console.log(" > ", packet);
        let raw = await this._reader.transmit(packet, 40);
        //console.log(" < ", raw);

        if (raw[raw.length - 2] !== 0x91) {
            throw Error("Invalid response");
        }

        let returnCode = raw.slice(-1)[0];
        raw = raw.slice(0,-2);

        if (returnCode !== this.constants.status.success && returnCode !== this.constants.status.moreFrames) {
            console.log("Card returned error code ", returnCode.toString(16));
            return [raw, returnCode];
        }

        if (handleAdditionalFrames) {
            while (returnCode === this.constants.status.moreFrames) {
                let result = await this._reader.transmit(this.wrap(this.constants.commands.AdditionalFrame, []), 40);
                //console.log(" A ", result);
                returnCode = result.slice(-1)[0];
                raw = Buffer.concat([raw, result.slice(0,-2)]);
                if (returnCode !== this.constants.status.success && returnCode !== this.constants.status.moreFrames) {
                    console.log("Card returned error code ", returnCode.toString(16));
                    return [raw, returnCode];
                }
                if (raw.length == 0) {
                    console.error("Warning: card expected more data");
                    break;
                }
            }
        }

        if (checkRxCmac) {
            let cmac = raw.slice(-8);
            raw = raw.slice(0, -8);
            let inputForCmacCalc = new Buffer.alloc(raw.length + 1);
            raw.copy(inputForCmacCalc);
            inputForCmacCalc[raw.length] = returnCode;
            let calccmac = await this.calculateCmac(inputForCmacCalc);
            if (Buffer.compare(cmac, calccmac.slice(0,8)) !== 0) {
                console.log("Response: Status ", returnCode, "CMAC: ", cmac, " Data: ", raw, "#", raw.length);
                console.log("RX CMAC", inputForCmacCalc, " = ", calccmac.slice(0,8));
                throw Error("Invalid cmac");
            }
        } else {
            //console.log("Response: Status ", returnCode, " Data: ", raw, "#", raw.length);
        }

        if (decryptRxData) { // Decrypt response
            raw = this.key.decrypt(raw, true);
        }

        return [raw, returnCode];
    }

    verifyCrc(buffer, dataLength, status = 0) {
        let inputCrc = buffer.readUint32LE(dataLength);
        let calcCrc = 0;
        if (this.key instanceof DesfireKeyAes) { // AES or 3K3DES
            let inputBuffer = Buffer.alloc(dataLength + 1);
            buffer.slice(0,dataLength).copy(inputBuffer);
            inputBuffer[dataLength] = status;
            calcCrc =  this.crc32(inputBuffer);
        } else { // DES or 3DES (legacy)
            let inputBuffer = Buffer.alloc(dataLength);
            buffer.slice(0,dataLength).copy(inputBuffer);
            calcCrc = this.crc16(inputBuffer);
        }
        if (inputCrc != calcCrc) console.log("CRC INVALID", buffer, dataLength, inputCrc.toString(16), calcCrc.toString(16));
        return (inputCrc == calcCrc);
    }
    
    crc32(data) {
        let poly = 0xEDB88320;
        let crc = 0xFFFFFFFF;
        for (let n = 0; n < data.length; n++) {
            crc ^= data[n];
            for (let b = 0; b < 8; b++) {
                if (crc & 1) {
                    crc = (crc >>> 1) ^ poly;
                } else {
                    crc = (crc >>> 1);
                }
            }
        }
        
        return crc >>> 0;
    }

    crc16(data) {
        let reg = 0x6363;
        for (let position = 0; position < data.length; position++) {
            let bt = data[position];
            bt = (bt ^ (reg & 0xFF)) & 0xFF;
            bt = (bt ^ (bt << 4)) & 0xFF;
            reg = ((reg >>> 8) ^ ((bt & 0xFFFF) << 8) ^ ((bt & 0xFFFF) << 3) ^ ((bt & 0xFFFF) >> 4)) & 0xFFFF;
        }

        return (reg >>> 0);
    }

    async calculateCmac(input) {
        let buffer = Buffer.from(input);
        let paddingLength = (buffer.length < this.key.blockSize) ? (this.key.blockSize - buffer.length) : ((this.key.blockSize - (buffer.length % this.key.blockSize)) % this.key.blockSize);
        if (paddingLength > 0) {
            paddingLength -= 1;
            buffer = Buffer.concat([buffer, Buffer.from([0x80])]);
            buffer = Buffer.concat([buffer, Buffer.from(new Array(paddingLength).fill(0))]);
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac2[index];
            }
        } else {
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac1[index];
            }
        }
        buffer = await this.key.encrypt(buffer, true);
        let result = Buffer.alloc(this.key.sessionIv.length);
        this.key.sessionIv.copy(result);
        return result;
    }

    async padAndEncrypt(input) {
        let buffer = Buffer.from(input);
        let paddingLength = (buffer.length < this.key.blockSize) ? (this.key.blockSize - buffer.length) : ((this.key.blockSize - (buffer.length % this.key.blockSize)) % this.key.blockSize);
        if (paddingLength > 0) {
            buffer = Buffer.concat([buffer, Buffer.from(new Array(paddingLength).fill(0))]);
        }
        buffer = await this.key.encrypt(buffer, true);
        let result = Buffer.alloc(this.key.sessionIv.length);
        this.key.sessionIv.copy(result);
        return buffer;
    }
    
    wrap(cmd, dataIn) {
        if (dataIn.length > 0) {
            return Buffer.from([0x90, cmd, 0x00, 0x00, dataIn.length, ...dataIn, 0x00]);
        } else {
            return Buffer.from([0x90, cmd, 0x00, 0x00, 0x00]);
        }
    }

    decryptAes(key, data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createDecipheriv("AES-128-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    // Security related commands

    async authenticateLegacy(keyId, key) {
        this.key = new DesfireKeyDes(keyId, key);
        await this.key.authenticate(this);
    }

    async changeKeySettings(settings) {
        if (!(settings instanceof DesfireKeySettings)) {
            throw new Error("Expected settings to be a DesfireKeySettings object");
        }
        let parameters = Buffer.alloc(1);
        parameters.writeUint8(settings.getSettings(), 0);
        let [data, returnCode] = await this.communicate(this.constants.commands.ChangeKeySettings, [], parameters, false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to change key settings (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getKeySettings() {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetKeySettings, [], null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("get key settings failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return new DesfireKeySettings(data);
    }

    async changeKeyAes(keyVersion, newKeyId, newKey, oldKey = null) {
        newKey = new DesfireKeyAes(newKeyId, newKey);

        if (!(newKey instanceof DesfireKeyAes)) {
            throw new Error("Expected the new key to be an AES key");
        }

        if (!(this.key instanceof DesfireKeyAes)) {
            throw new Error("Expected the current key to be an AES key");
        }

        let keyNo = newKey.authenticationkeyIdentifier;

        if (this.key.authenticationkeyIdentifier === keyNo) {
            if (oldKey !== null) {
                if (Buffer.compare(oldKey, this.key.authenticationKey) !== 0) {
                    throw new Error("Different old key supplied while changing current key");
                }
                oldKey = new DesfireKeyAes(0, oldKey);
            }
        } else if (oldKey === null) {
            throw new Error("Old key required when changing different key");
        }

        if (this.appId === 0x000000) { // Changing PICC master key
            if (keyNo !== 0x00) {
                throw new Error("When changing PICC master key only key 0 is valid");
            }
        } else if (keyNo > 0x0F) {
            throw new Error("Key number out of range (0-15)");
        }

        let parameters = Buffer.alloc(1);
        let keyNoAndType = keyNo;
        if (this.appId === 0x000000) {
            keyNoAndType |= this.constants.keyType.AES;
        }
        parameters.writeUint8(keyNoAndType, 0);

        let encryptedParameters = Buffer.alloc(17);
        newKey.authenticationKey.copy(encryptedParameters, 0);
        encryptedParameters.writeUint8(keyVersion, 16);

        if (this.key.authenticationkeyIdentifier !== keyNo) { // Changing diffent key
            for (let byte = 0; byte < newKey.keyLength; byte++) { // XOR new key data with old key
                encryptedParameters[byte] ^= oldKey.authenticationKey[byte];
            }
            let newKeyCrc = this.crc32(newKey.authenticationKey);
            let newKeyCrcBuffer = Buffer.alloc(4);
            newKeyCrcBuffer.writeUInt32LE(newKeyCrc);
            var [data, returnCode] = await this.communicate(this.constants.commands.ChangeKey, parameters, encryptedParameters, false, true, false, false, newKeyCrcBuffer);
        } else {
            var [data, returnCode] = await this.communicate(this.constants.commands.ChangeKey, parameters, encryptedParameters, false, false);
            this.key = null; // Currently authenticated key was changed, we are no longer authenticated
        }

        if (returnCode !== this.constants.status.success) {
            throw new Error("change key (AES) failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getKeyVersion(keyNo) {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetKeyVersion, [keyNo], null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("get key version failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data.readUint8(0);
    }

    // PICC level commands

    async createApplication(aAppId, aSettings, aKeyCount, aKeyType) {
        if (typeof aAppId !== "number" || aAppId < 0 || aAppId >= Math.pow(2, 8 * 3)) { // 3 bytes
            throw Error("Application identifier needs to be a positive number of at most three bytes");
        }
        let parameters = Buffer.alloc(5);
        writeUint24LE(parameters, aAppId, 0);
        parameters.writeUint8(aSettings, 3);
        parameters.writeUint8(aKeyCount | aKeyType, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands["CreateApplication"], parameters);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Create application failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async deleteApplication(aAppId) {
        if (typeof aAppId !== "number" || aAppId < 0 || aAppId >= Math.pow(2, 8 * 3)) { // 3 bytes
            throw Error("Application identifier needs to be a positive number of at most three bytes");
        }
        let parameters = Buffer.alloc(3);
        writeUint24LE(parameters, aAppId, 0);
        let [data, returnCode] = await this.communicate(this.constants.commands.DeleteApplication, parameters);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Delete application failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getApplicationIdentifiers() {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetApplicationIdentifiers);
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to get application identifiers (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }

        let apps = [];
        for (let index = 0; index < data.length; index += 3) {
            apps.push(Buffer.concat([data.slice(index, index+3), Buffer.from([0x00])]).readUint32LE());
        }
        return apps;
    }

    async selectApplication(appId) {
        if (typeof appId === "number") {
            let newAppId = Buffer.alloc(4);
            newAppId.writeUint32LE(appId);
            appId = newAppId.slice(0,3);
        }
        let [data, returnCode] = await this.communicate(this.constants.commands.SelectApplication, appId);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Select application failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        this.key = null;
        this.appId = appId;
    }

    async formatPicc() {
        let [data, returnCode] = await this.communicate(this.constants.commands.FormatPicc);
        if (returnCode !== this.constants.status.success) {
            throw new Error("format failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getVersion() {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetVersion);
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to get card version (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return new DesfireCardVersion(data);
    };

    // Application level commands

    async getFileIdentifiers() {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetFileIdentifiers, [], null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get file identifiers (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data;
    }

    async getFileSettings(fileNo) { // TEST
        let [data, returnCode] = await this.communicate(this.constants.commands.GetFileSettings, [fileNo], null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get file settings (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data; // TBD: parse result
    }

    async changeFileSettings() { // Encrypted command
        throw new Error("Not implemented");
    }

    async createStandardDataFile(fileNo, commsCmac, commsEncrypted, readAccess, writeAccess, readAndWriteAccess, changeAccessRights, fileSize) {
        if ((typeof fileNo !== "number") || (fileNo < 0) || (fileNo > 0x0F)) {
            throw Error("FileNo should be a number in the range 0 to 15");
        }
        if ((typeof fileNo !== "number") || (fileNo < 0) || (fileNo > 0x0F)) {
            throw Error("FileNo should be a number in the range 0 to 15");
        }
        let params = Buffer.alloc(7);
        params.writeUint8(fileNo, 0);
        if (commsEncrypted) {
            params.writeUint8(this.constants.communicationSettings.encrypted, 1);
        } else if (commsCmac) {
            params.writeUint8(this.constants.communicationSettings.cmac, 1);
        } else {
            params.writeUint8(this.constants.communicationSettings.plain, 1);
        }
        params.writeUint16LE((changeAccessRights & 0xF) + ((readAndWriteAccess & 0xF) << 4) + ((writeAccess & 0xF) << 8) + ((readAccess & 0xF) << 12), 2);
        writeUint24LE(params, fileSize, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.CreateStandardDataFile, params, null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to create standard data file (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async createBackupDataFile(fileNo, commsCmac, commsEncrypted, readAccess, writeAccess, readAndWriteAccess, changeAccessRights, fileSize) {
        let params = Buffer.alloc(7);
        params.writeUint8(fileNo, 0);
        if (commsEncrypted) {
            params.writeUint8(this.constants.communicationSettings.encrypted, 1);
        } else if (commsCmac) {
            params.writeUint8(this.constants.communicationSettings.cmac, 1);
        } else {
            params.writeUint8(this.constants.communicationSettings.plain, 1);
        }
        params.writeUint16LE((changeAccessRights & 0xF) + ((readAndWriteAccess & 0xF) << 4) + ((writeAccess & 0xF) << 8) + ((readAccess & 0xF) << 12), 2);
        writeUint24LE(params, fileSize, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.CreateBackupDataFile, params, null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to create standard data file (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data;
    }

    async createValueFile() {
        throw new Error("Not implemented");
    }

    async createLinearRecordFile() {
        throw new Error("Not implemented");
    }

    async createCyclicRecordFile() {
        throw new Error("Not implemented");
    }

    async deleteFile(fileNo) {
        let [data, returnCode] = await this.communicate(this.constants.commands.DeleteFile, [fileNo], null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get file settings (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data; 
    }

    // Data manipulation commands

    async readDataPlain(aFileId, aOffset = 0, aLength = 0) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aLength, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.ReadData, parameters);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to read file contents [plain] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data;
    };

    async readDataCmac(aFileId, aOffset = 0, aLength = 0) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aLength, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.ReadData, parameters, null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to read file contents [cmac] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data;
    };

    async readDataEncrypted(aFileId, aOffset = 0, aLength = 0) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aLength, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.ReadData, parameters, null, true, false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to read file contents [encrypted] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        if (!this.verifyCrc(data, aLength)) {
            throw new Error("Invalid CRC");
        }
        return data.slice(0,aLength);
    };

    async writeDataPlain(aFileId, aData, aOffset = 0) {
        let parameters = Buffer.alloc(7 + aData.length);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aData.length, 4);
        aData.copy(parameters, 7);
        let [data, returnCode] = await this.communicate(this.constants.commands.WriteData, parameters, null, false, false);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to write file contents [plain] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async writeDataCmac(aFileId, aData, aOffset = 0) {
        let parameters = Buffer.alloc(7 + aData.length);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aData.length, 4);
        aData.copy(parameters, 7);
        let [data, returnCode] = await this.communicate(this.constants.commands.WriteData, parameters, null, true, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to write file contents [cmac] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async writeDataEncrypted(aFileId, aData, aOffset = 0) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aData.length, 4);
        let [data, returnCode] = await this.communicate(this.constants.commands.WriteData, parameters, aData, false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to write file contents [encrypted] (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getValue() {
        throw new Error("Not implemented");
    }

    async credit() {
        throw new Error("Not implemented");
    }

    async debit() {
        throw new Error("Not implemented");
    }

    async limitedCredit() {
        throw new Error("Not implemented");
    }

    async writeRecord() {
        throw new Error("Not implemented");
    }

    async readRecords() {
        throw new Error("Not implemented");
    }

    async clearRecordFile() {
        throw new Error("Not implemented");
    }

    async commitTransaction() {
        throw new Error("Not implemented");
    }

    async abortTransaction() {
        throw new Error("Not implemented");
    }

    // Desfire EV1 instructions

    async ev1AuthenticateIso(keyId, key) {
        throw new Error("Not implemented");
    }

    async ev1AuthenticateAes(keyId, key) {
        this.key = new DesfireKeyAes(keyId, key);
        await this.key.authenticate(this);
    }

    async ev1FreeMem() {
        let [data, returnCode] = await this.communicate(this.constants.commands.Ev1FreeMem);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get free memory (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return Buffer.concat([data.slice(0,3), Buffer.from([0x00])]).readUint32LE();
    };

    async ev1GetDfNames() {
        throw new Error("Not implemented");
    }
    
    async ev1GetCardUid() {
        let [data, returnCode] = await this.communicate(this.constants.commands.Ev1GetCardUid, [], null, true, false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get card UID (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        if (!this.verifyCrc(data, 7)) {
            throw new Error("Invalid CRC");
        }
        return data.slice(0,7);
    };

    async ev1GetIsoFileIdentifiers() {
        throw new Error("Not implemented");
    }

    async ev1SetConfiguration(permanentlyDisableCardFormatting, permanentlyEnableRandomUid) {
        let parameters = Buffer.alloc(1);
        parameters.writeUint8(0, 0);
        let cardConfigBuffer = Buffer.alloc(1);
        let cardConfig = 0;
        if (permanentlyDisableCardFormatting) {
            cardConfig |= (1 << 0);
        }
        if (permanentlyEnableRandomUid) {
            cardConfig |= (1 << 1);
        }
        cardConfigBuffer.writeUint8(cardConfig, 0);
        let [data, returnCode] = await this.communicate(this.constants.commands.Ev1SetConfiguration, parameters, cardConfigBuffer, false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Set configuration failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }
}

module.exports = {DesfireCard: DesfireCard, DesfireKeySettings: DesfireKeySettings};
