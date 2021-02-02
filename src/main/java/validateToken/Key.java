package validateToken;

public class Key {
	private KeyData[] keys;
	
	public Key() {
		super();
			}

	public Key(KeyData[] keys) {
		this.keys = keys;
	}

	public KeyData[] getKeys() {
		return keys;
	}

	public void setKeys(KeyData[] keys) {
		this.keys = keys;
	}
}