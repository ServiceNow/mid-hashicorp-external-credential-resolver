# MID Server External Credential Resolver for Hashicorp Vault

This is the ServiceNow MID Server custom external credential resolver for the Hashicorp vault credential storage.

# Pre-requisites:

HashiCorp External Credential Resolver requires JDK 1.8 or newer
Eclipse or any equivalent IDE

# Steps to build
* Clone this repository.
* Import the project in Eclipse or any IDE.
* Update MID Server agent path in pom.xml to point to valid MID Server location.
* Update the code in CredentialResolver.java to customize anything.
* Use below maven command or IDE (Eclipse or Intellij) maven build option to build the jar.

	> mvn clean package

* hashicorp-external-credentials-0.0.1-SNAPSHOT.jar will be generated under target folder.

# Steps to install and use HashiCorp vault as external credential resolver

* Make sure that “External Credential Storage” plugin (com.snc.discovery.external_credentials) is installed in your ServiceNow instance.
* Download [Vault Java Driver](https://github.com/BetterCloud/vault-java-driver) (vault-java-driver-5.1.0.jar - dependency in pom.xml) file from [maven repository](https://mvnrepository.com/artifact/com.bettercloud/vault-java-driver/5.1.0).
* Import the downloaded vault-java-driver-5.1.0.jar file in ServiceNow instance under MID Server - JAR Files.
	- Navigate to MID Server – JAR Files
	- Create a New Record by clicking New
	- Name it “vault-java-driver”, version 5.1 and attach this file to the record.
	- Click Submit
* Import the hashicorp-external-credentials-0.0.1-SNAPSHOT.jar file from target folder in ServiceNow instance.
	- Navigate to MID Server – JAR Files
	- Create a New Record by clicking New
	- Name it “HashiCorpCredentialResolver”, version 0.0.1 and attach hashicorp-external-credentials-0.0.1-SNAPSHOT.jar from target folder.
	- Click Submit
* Update the config.xml in MID Server with below parameters and restart the MID Server.

	`<parameter name="ext.cred.hashicorp.vault.address" value="<hashicorp-vault-url>"/>` 
	
	`<parameter name="ext.cred.hashicorp.vault.token" secure="true" value="<hashicorp-root-token>"/>`

* Create Credential in the instance with "External credential store" flag activated.
* Ensure that the "Credential ID" match a secret path in your Hashicorp credential store (ex: kv/mycred)
* Ensure that the secret in the vault contain keys matching the ServiceNow credential record fields (ex: username, password)

# To use non-root user to connect to HashiCorp server, follow below steps.

* Follow below link to create userpass in HashiCorp vault.

	https://www.vaultproject.io/api-docs/auth/userpass
	
* Use below code to get the token for the given username and password.

	String hashicorpVaultAddress = "";
	
	String hashiCorpUser = "username";
	
	String hashiCorpPassword = "password";
	
	final VaultConfig authConfig = new VaultConfig()
			.address(hashicorpVaultAddress)
			.openTimeout(60)    
			.readTimeout(60)    
			.sslConfig(new SslConfig().build())
			.build();
			
	final Vault authVault = new Vault(authConfig);
	
	com.bettercloud.vault.response.AuthResponse authResp = authVault.auth().loginByUserPass(hashiCorpUser, hashiCorpPassword);
	
	//This token can be used for connecting to HashiCorp
	
	String hashicorpVaultToken = authResp.getAuthClientToken();

# To connect to SSL enabled HashiCorp vault server (HTTPS), follow below steps.

* Follow below link to setup SSL TCP listener in HashiCorp vault server.

	https://www.vaultproject.io/docs/configuration/listener/tcp
	
* Follow below link to update the HashiCorp credential resolved code to connect to HashiCorp using HTTPS.

	https://github.com/BetterCloud/vault-java-driver#ssl-config
  

	


