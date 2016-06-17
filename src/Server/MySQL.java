package Server;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

 


public class MySQL {
 
	
	public static String table = "passwordsandcertificates";
	public static String column1 = "owner";
	public static String column2 = "password";
	public static String column3 = "certificate_ec";
	public static String column4 = "ec_validto";
	public static String column5 = "certificate_rsa";
	public static String column6 = "rsa_validto";
	public static String value = "CN=MyTestCACert, OU=SY, O=IHP, L=FFO, ST=Brandenburg, C=DE";
	
    // JDBC URL, username and password of MySQL server
    private static final String url = "jdbc:mysql://localhost:13306/cadatabase";
    private static final String user = "root";
    private static final String password = "root";
 
    // JDBC variables for opening and managing connection
    private static Connection con;
    private static Statement stmt;
    private static ResultSet rs;
  
    
    /*
     * Show all data from DB
     */
    public static void readallinDB(){
        String read = "select * from passwordsandcertificates";
        try {
            // opening database connection to MySQL server
            con = DriverManager.getConnection(url, user, password);
            // getting Statement object to execute query
            stmt = con.createStatement();
        // executing SELECT query
        try {
			rs = stmt.executeQuery(read);
			while (rs.next()) {
		     	String db = "";
		       	for (int i = 1; i < 6; i++) {
		       		String db1 = rs.getString(i);
		       		db = db + db1 + " ";
				}
		        System.out.println(db);
			 }
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        } catch (SQLException sqlEx) {
            sqlEx.printStackTrace();
        } finally {
            try { con.close(); } catch(SQLException se) {}
            try { stmt.close(); } catch(SQLException se) {}
            try { rs.close(); } catch(SQLException se) {}
        }
    }
    
    
    /*
     *Write a new string into DB 
     */
    public static void writeDB(String column, String value) throws SQLException{
        try {
            con = DriverManager.getConnection(url, user, password);
            stmt = con.createStatement();
            String write = "INSERT INTO ebpasswords.passwordsandcertificates (" + column + ") VALUES (" + value + ");";
            stmt.executeUpdate(write);
        	} catch (SQLException sqlEx) {
        		sqlEx.printStackTrace();
        } finally {
            try { con.close(); } catch(SQLException se) {}
            try { stmt.close(); } catch(SQLException se) {}
            try { rs.close(); } catch(SQLException se) {}
        }
    }
    
    
    /*
     * Read cell from DB 
     */
    public static String readDB(String table, String column1, String column2, String value2) throws SQLException{
        //SELECT column1 FROM table WHERE column2 = value2
    	String myquery = "SELECT " + column1 + " FROM " + table + " WHERE " + column2 + " =?";
        String result = null;
        try {
            con = DriverManager.getConnection(url, user, password);
            stmt = con.createStatement();
            PreparedStatement ps = con.prepareStatement(myquery);
            ps.setString(1, value2);
            rs = ps.executeQuery();
            while (rs.next()) {
            	result = rs.getString(1);
            	System.out.println(result);
            }    	
        } catch (SQLException sqlEx) {
            sqlEx.printStackTrace();
        } finally {
            try { con.close(); } catch(SQLException se) {}
            try { stmt.close(); } catch(SQLException se) {}
            try { rs.close(); } catch(SQLException se) {}
        }
        return result;
    }
    
    
    /*
     * Check if value is in the DB
     */
    public static String checkCell(String table, String column, String value) throws SQLException{
        //SELECT column1 FROM table WHERE column2 = value2
    	String myquery = "SELECT COUNT(*) FROM " + table + " WHERE " + column + " =?";
        String result = null;
        try {
            con = DriverManager.getConnection(url, user, password);
            stmt = con.createStatement();
            PreparedStatement ps = con.prepareStatement(myquery);
            ps.setString(1, value);
            rs = ps.executeQuery();
            while (rs.next()) {
            	result = rs.getString(1);
            	System.out.println(result);
            }    	
        } catch (SQLException sqlEx) {
            sqlEx.printStackTrace();
        } finally {
            try { con.close(); } catch(SQLException se) {}
            try { stmt.close(); } catch(SQLException se) {}
            try { rs.close(); } catch(SQLException se) {}
        }
        System.out.println("CERT check result = " + result);
        return result;
    }
    
    /*
     * Update data in DB
     */
    public static void UpdateDB(String table, String column1, String column2, String value1, String value2) throws SQLException{
        try {
            con = DriverManager.getConnection(url, user, password);
            stmt = con.createStatement();
            //UPDATE table SET column1 = "?" WHERE column2 = "?"
            String myquery = "UPDATE " + table + " SET " + column1 + " =? WHERE " + column2 + " =?";
            PreparedStatement ps = con.prepareStatement(myquery);
            ps.setString(1, value1);
            ps.setString(2, value2);        
            ps.executeUpdate();
            System.out.println("Database was updated");
        	} catch (SQLException sqlEx) {
        		sqlEx.printStackTrace();
        } finally {
        	try { con.close(); } catch(SQLException se) {}
        	try { stmt.close(); } catch(SQLException se) {}
        	try { rs.close(); } catch(SQLException se) {}
        }
    }
    
    /*
     * Delete data from DB
     */
    public static void delDB(String table, String column, String value) throws SQLException{
        try {
            con = DriverManager.getConnection(url, user, password);
            stmt = con.createStatement();
            //DELETE FROM table WHERE column = value
            String myquery = "DELETE FROM " + table + " WHERE " + column + " =?";
            PreparedStatement ps = con.prepareStatement(myquery);
            ps.setString(1, value);
            ps.executeUpdate();
            System.out.println("String with value " + value + " was deleted from the table");
        	} catch (SQLException sqlEx) {
        		sqlEx.printStackTrace();
        } finally {
        	try { con.close(); } catch(SQLException se) {}
        	try { stmt.close(); } catch(SQLException se) {}
        	try { rs.close(); } catch(SQLException se) {}
        }
    }
}

