	'use strict'

	/** ******* Imports ********/

	const {
	/* The following functions are all of the cryptographic
	primatives that you should need for this assignment.
	See lib.js for details on usage. */
	bufferToString,
	genRandomSalt,
	generateEG, // async
	computeDH, // async
	verifyWithECDSA, // async
	HMACtoAESKey, // async
	HMACtoHMACKey, // async
	HKDF, // async
	encryptWithGCM, // async
	decryptWithGCM,
	cryptoKeyToJSON, // async
	govEncryptionDataStr
	} = require('./lib')

	/** ******* Implementation ********/

	class MessengerClient {
	constructor (certAuthorityPublicKey, govPublicKey) {
		// the certificate authority DSA public key is used to
		// verify the authenticity and integrity of certificates
		// of other users (see handout and receiveCertificate)

		// you can store data as needed in these objects.
		// Feel free to modify their structure as you see fit.
		this.caPublicKey = certAuthorityPublicKey
		this.govPublicKey = govPublicKey
		this.conns = {} // data for each active connection
		this.certs = {} // certificates of other users
		this.EGKeyPair = {} // keypair from generateCertificate
	}

	/**
	 * Generate a certificate to be stored with the certificate authority.
	 * The certificate must contain the field "username".
	 *
	 * Arguments:
	 *   username: string
	 *
	 * Return Type: certificate object/dictionary
	 */
	async generateCertificate (username) {
		const certificate = {};
		certificate.username = username;
		const keyPair = await generateEG();
		certificate.pubKey = keyPair.pub;
		
		this.EGKeyPair = {certPk: keyPair.pub, certSk: keyPair.sec};
		return certificate;
	}

	/**
	 * Receive and store another user's certificate.
	 *
	 * Arguments:
	 *   certificate: certificate object/dictionary
	 *   signature: ArrayBuffer
	 *
	 * Return Type: void
	 */
	async receiveCertificate (certificate, signature) {
		//check this is a valid signature on the certificate

		const valid = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature)
		if(!valid) throw("invalid signature provided");
		this.certs[certificate.username] = certificate;
	}

	/**
	 * Generate the message to be sent to another user.
	 *
	 * Arguments:
	 *   name: string
	 *   plaintext: string
	 *
	 * Return Type: Tuple of [dictionary, ArrayBuffer]
	 */
	async sendMessage (name, plaintext) 
	{
		if (!(name in this.conns)) 
		{
			const senderPublicKey = this.certs[name].pubKey;

			const rawRootKey = await computeDH(this.EGKeyPair.certSk, senderPublicKey);
			const freshPair = await generateEG();
			this.EGKeyPair[name] = {pubKey: freshPair.pub, secKey: freshPair.sec};

			const hkdfInputKey = await computeDH(this.EGKeyPair[name].secKey, senderPublicKey);

			const [rootKey, chainKey] = await HKDF(hkdfInputKey, rawRootKey, "ratchet-salt");
			
			this.conns[name] = {rootKey: rootKey, chainKeySend: chainKey};

			this.conns[name].seenPks = new Set()
		}
		const chainKeySend = await HMACtoHMACKey(this.conns[name].chainKeySend, "ck-str");
		const mk = await HMACtoAESKey(this.conns[name].chainKeySend, "mk-str");
		const mkBuffer = await HMACtoAESKey(this.conns[name].chainKeySend, "mk-str", true);
		this.conns[name].chainKeySend = chainKeySend; 

		const ivGov = genRandomSalt();
		const receiverIV = genRandomSalt();
		const newGovPair = await generateEG();

		const dhSecret = await computeDH(newGovPair.sec, this.govPublicKey); // pub^sec --> (g^b)^a
		const dhSecretKey = await HMACtoAESKey(dhSecret, govEncryptionDataStr); 
		const cGov = await encryptWithGCM(dhSecretKey, mkBuffer, ivGov); 
		
		const header = {
			vGov: newGovPair.pub, 
			cGov: cGov, 
			receiverIV: receiverIV, 
			ivGov: ivGov,
			pkSender: this.EGKeyPair[name].pubKey 
		};

		const ciphertext = await encryptWithGCM(mk, plaintext, receiverIV, JSON.stringify(header));

		return [header, ciphertext];
	}

	/**
	 * Decrypt a message received from another user.
	 *
	 * Arguments:
	 *   name: string
	 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
	 *
	 * Return Type: string
	 */
	async receiveMessage (name, [header, ciphertext]) 
	{
		if (!(name in this.conns)) 
		{
			const senderCertPk = this.certs[name].pubKey;
			const rawRootKey = await computeDH(this.EGKeyPair.certSk, senderCertPk);
			const hkdfInputKey = await computeDH(this.EGKeyPair.certSk, header.pkSender);
			const [rootKey, chainKey] = await HKDF(hkdfInputKey, rawRootKey, "ratchet-salt");

			const freshPair = await generateEG();
			this.EGKeyPair[name] = {pubKey: freshPair.pub, secKey: freshPair.sec};

			const dhResult = await computeDH(this.EGKeyPair[name].secKey, header.pkSender);

			const [finalRootKey, chainKeySend] = await HKDF(dhResult, rootKey, "ratchet-salt");
			
			this.conns[name] = {rootKey: finalRootKey, chainKeyRecv: chainKey, chainKeySend: chainKeySend};

			this.conns[name].seenPks = new Set()

		} 
		else if (!(this.conns[name].seenPks.has(header.pkSender))) 
		{
			const firstDhOutput = await computeDH(this.EGKeyPair[name].secKey, header.pkSender);
			let [rootKeyFirst, chainKeyRecv] = await HKDF(firstDhOutput, this.conns[name].rootKey, "ratchet-salt"); //see Signal diagram

			const freshPair = await generateEG();
			this.EGKeyPair[name] = {pubKey: freshPair.pub, secKey: freshPair.sec}

			const secondDhOutput = await computeDH(this.EGKeyPair[name].secKey, header.pkSender);
			const [rootKey, chainKeySend] = await HKDF(secondDhOutput, rootKeyFirst, "ratchet-salt"); //see Signal diagram
			this.conns[name].rootKey = rootKey;
			this.conns[name].chainKeySend = chainKeySend;
			this.conns[name].chainKeyRecv = chainKeyRecv;
		}

		const chainKeyRecv = await HMACtoHMACKey(this.conns[name].chainKeyRecv, "ck-str");
		const mk = await HMACtoAESKey(this.conns[name].chainKeyRecv, "mk-str");
		
		//update chainKeyRecv and the public key of the last sender
		this.conns[name].chainKeyRecv = chainKeyRecv;
		this.conns[name].seenPks.add(header.pkSender)
		
		const plaintext = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
		return bufferToString(plaintext);
	}
};

module.exports = {
MessengerClient
}
