package pl.legit.passwordwallet;

record User(String username, String passwordHash, byte[] salt, HashFunction hash) {
    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public byte[] getSalt() {
        return salt;
    }

    public HashFunction getHash() {
        return hash;
    }
}
