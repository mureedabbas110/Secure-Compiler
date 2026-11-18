public class VulnerableApp {
    public static void main(String[] args) {
        String password = "hardcoded_admin_pass";
        String cmd = args[0];
        Runtime.getRuntime().exec("sh " + cmd);
        String sql = "SELECT * FROM logs WHERE tag = " + cmd;
        stmt.executeQuery(sql);
    }
}
