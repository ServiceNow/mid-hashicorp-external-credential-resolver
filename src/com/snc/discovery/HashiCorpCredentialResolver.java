package com.snc.discovery;

import java.util.HashMap;
import java.util.Map;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.service_now.mid.services.Config;

/**
 * Custom External Credential Resolver for HashiCorp credential vault.
 * Use Vault Java Driver a community written zero-dependency Java client from https://bettercloud.github.io/vault-java-driver/
 */
public class HashiCorpCredentialResolver {

	// These are the permissible names of arguments passed INTO the resolve()
	// method.

	// the string identifier as configured on the ServiceNow instance...
	public static final String ARG_ID = "id";

	// a dotted-form string IPv4 address (like "10.22.231.12") of the target
	// system...
	public static final String ARG_IP = "ip";

	// the string type (ssh, snmp, etc.) of credential as configured on the
	// instance...
	public static final String ARG_TYPE = "type";

	// the string MID server making the request, as configured on the
	// instance...
	public static final String ARG_MID = "mid";

	// These are the permissible names of values returned FROM the resolve()
	// method.

	// the string user name for the credential, if needed...
	public static final String VAL_USER = "user";

	// the string password for the credential, if needed...
	public static final String VAL_PSWD = "pswd";

	// the string pass phrase for the credential if needed:
	public static final String VAL_PASSPHRASE = "passphrase";

	// the string private key for the credential, if needed...
	public static final String VAL_PKEY = "pkey";
	
	public static final String HASHICORP_VAULT_ADDRESS_PROPERTY = "mid.ext.cred.hashicorp.vault.address";
	public static final String HASHICORP_VAULT_TOKEN_PROPERTY = "mid.ext.cred.hashicorp.vault.token";

	//Remove hard-coded values and read them from config.xml
	private String hashicorpVaultAddress = "";
	private String hashicorpVaultToken = "";

	public HashiCorpCredentialResolver() {
		loadProps();
	}

	private void loadProps() {
		//Load vault details from MID config.xml parameters
		hashicorpVaultAddress = Config.get().getProperty(HASHICORP_VAULT_ADDRESS_PROPERTY);
		if(isNullOrEmpty(hashicorpVaultAddress))
			throw new RuntimeException("[Vault] INFO - HashiCorpCredentialResolver " + HASHICORP_VAULT_ADDRESS_PROPERTY + " not set!");

		hashicorpVaultToken = Config.get().getProperty(HASHICORP_VAULT_TOKEN_PROPERTY);
		if(isNullOrEmpty(hashicorpVaultToken))
			throw new RuntimeException("[Vault] INFO - HashiCorpCredentialResolver " + HASHICORP_VAULT_TOKEN_PROPERTY + " not set!");
	}

	/**
	 * Resolve a credential.
	 */
	public Map<String, String> resolve(Map<String, String> args) {
		
		String id = (String) args.get(ARG_ID);
		String type = (String) args.get(ARG_TYPE);

		String username = "";
		String password = "";
		String passphrase = "";
		String private_key = "";

		if(id == null || type == null)
			throw new RuntimeException("Invalid credential Id or type found.");

		// Connect to vault and retrieve credential
		try {
			final VaultConfig config = new VaultConfig()
					.address(hashicorpVaultAddress)
					.token(hashicorpVaultToken)
					.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
					.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
					.sslConfig(new SslConfig().build())   // See "SSL Config" section below
					.build();
			final Vault vault = new Vault(config);
			LogicalResponse response = vault.logical().read(id);
			switch(type) {
			// for below listed credential type , just retrieve user name and password 
			case "windows":
			case "ssh_password": // Type SSH
			case "vmware":
			case "jdbc":
			case "jms": 
			case "basic":
				
				username = response.getData().get("username"); // Static Secret
				password = response.getData().get("password"); // Static Secret
				
				//TODO: find working API for AD
				if ( id.contains("ad/creds/") ) {
					//String role = id.substring(id.lastIndexOf("/")+1);
					//username = vault.activedirectory().getRole(role).getData().get("service_account_name"); // AD Secret
					//password = vault.activedirectory().creds(role).getData().get("password"); // AD Secret
				}

				break;
				// for below listed credential type , retrieve user name, password, ssh_passphrase, ssh_private_key
			case "ssh_private_key": 
			case "sn_cfg_ansible": 
			case "sn_disco_certmgmt_certificate_ca":
			case "cfg_chef_credentials":
			case "infoblox": 
			case "api_key":
				// Read operation
				username = response.getData().get("username");
				password = response.getData().get("password");
				passphrase = response.getData().get("ssh_passphrase");
				private_key = response.getData().get("ssh_private_key");
				
				break;
			case "aws": ; // access_key, secret_key 	// AWS Support
				username = response.getData().get("access_key");
				password = response.getData().get("secret_key");
				
				break;

			case "ibm": ; // softlayer_user, softlayer_key, bluemix_key
			case "azure": ; // tenant_id, client_id, auth_method, secret_key
			case "gcp": ; // email , secret_key
			default:
				System.err.println("[Vault] INFO - HashiCorpCredentialResolver, not implemented credential type!");
				break;
			}
		} 
		catch (VaultException e) {
			// Catch block
			System.err.println("### Unable to connect to Vault: " + hashicorpVaultAddress + " #### ");
			e.printStackTrace();
		}
		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<String, String>();
		result.put(VAL_USER, username);
		result.put(VAL_PSWD, password);
		result.put(VAL_PKEY, private_key);
		result.put(VAL_PASSPHRASE, passphrase);
		return result;
	}

	private static boolean isNullOrEmpty(String str) {
		if(str != null && !str.isEmpty())
			return false;
		return true;
	}
	
	/**
	 * Return the API version supported by this class.
	 */
	public String getVersion() {
		return "2.0";
	}

	public static void main(String[] args) {
		HashiCorpCredentialResolver obj = new HashiCorpCredentialResolver();
		// obj.loadProps();
		// use your local details for testing.
		obj.hashicorpVaultAddress = "<hashicorp url>";
		obj.hashicorpVaultToken = "<token>";

		Map<String, String> map = new HashMap<>();
		map.put(ARG_ID, "kv/windowscred");
		map.put(ARG_TYPE, "windows");

		Map<String, String> result = obj.resolve(map );
		System.out.println(result.toString());
	}
}