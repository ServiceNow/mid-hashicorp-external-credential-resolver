# MID Server External Credential Resolver for Hashicorp Vault

This is the ServiceNow MID Server custom external credential resolver for the Hashicorp vault credential storage.

# Pre-requisites:

HashiCorp External Credential Resolver requires JDK 1.8 or newer
Eclipse or any equivalent IDE

# Steps to build
* Clone this repository.
* Import the project in Eclipse or any IDE.
* Update MID Server agent path in pom.xml to point to valid MID Server location.
* Update the code in HashiCorpCredentialResolver.java to customize anything.
* Use below maven command or IDE (Eclipse or Intellij) maven build option to build the jar.

	> mvn clean package

* hashicorp-external-credentials-0.0.1-SNAPSHOT.jar will be generated under target folder.

# Steps to install and use HashiCorp vault as external credential resolver

* Make sure that “External Credential Storage” plugin (com.snc.discovery.external_credentials) is installed in your ServiceNow instance.
* Download [Vault Java Driver](https://github.com/BetterCloud/vault-java-driver) (vault-java-driver-5.1.0.jar - dependency in pom.xml) file from [maven repository](https://mvnrepository.com/artifact/com.bettercloud/vault-java-driver/5.1.0).
* Import the downloaded vault-java-driver-5.1.0.jar file in ServiceNow instance under MID Server - JAR Files.
	a. Navigate to MID Server – JAR Files
	b. Create a New Record by clicking New
	c. Name it “vault-java-driver”, version 5.1 and attach this file to the record.
	d. Click Submit
* Import the hashicorp-external-credentials-0.0.1-SNAPSHOT.jar file from target folder in ServiceNow instance.
	a. Navigate to MID Server – JAR Files
	b. Create a New Record by clicking New
	c. Name it “HashiCorpCredentialResolver”, version 0.0.1 and attach hashicorp-external-credentials-0.0.1-SNAPSHOT.jar from target folder.
	d. Click Submit
* Update the config.xml in MID Server with below parameters and restart the MID Server.

	<parameter name="mid.ext.cred.hashicorp.vault.address" value="<hashicorp-vault-url>"/> 
	<parameter name="mid.ext.cred.hashicorp.vault.token" secure="true" value="<hashicorp-root-token>"/>

* Create Credential in the instance with "External credential store" flag activated.
* Ensure that the "Credential ID" match a secret path in your Hashicorp credential store (ex: kv/mycred)
* Ensure that the secret in the vault contain keys matching the ServiceNow credential record fields (ex: username, password)


