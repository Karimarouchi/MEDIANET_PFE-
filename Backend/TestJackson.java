import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import java.io.File;

public class TestJackson {
    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
        try {
            File f = new File(args[0]);
            System.out.println("File size: " + f.length());
            JsonNode root = mapper.readTree(f);
            System.out.println("Parse OK");
            JsonNode servers = root.path("server_scan_results");
            System.out.println("servers: " + servers.size());
            JsonNode scan = servers.get(0);
            System.out.println("scan_status: " + scan.path("scan_status").asText());
        } catch (Exception e) {
            System.out.println("EXCEPTION: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
}
