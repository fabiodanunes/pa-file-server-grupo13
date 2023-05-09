import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

/**
 * This class represents the file handler. It has the methods for reading and writing text files.
 */
public class FileHandler {

    /**
     * Reads a text file and returns the result in bytes.
     *
     * @param path the path of the file to read
     *
     * @return the content of the file in bytes
     */
    public static byte[] readFile ( String path ) {
        File file = new File(path);
        byte[] fileBytes = new byte[(int) file.length()];
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(fileBytes);
            fileInputStream.close();
        }
        catch (IOException e){
            System.out.println("Error reading file!");
            e.printStackTrace();
        }
        return fileBytes;
    }

    /**
     * Writes to a text file
     *
     * @param path path to the file to write
     * @param content byte array with the content to be written
     * @param append true when the content should be added to current file content,
     *               false when it should replace it
     */
    public static void writeFile ( String path , byte[] content, boolean append ) {
        BufferedWriter writer;
        try {
            writer = new BufferedWriter(new FileWriter(path,append));
            writer.write(new String(content));
            writer.close();
        } catch (IOException e) {
            System.out.println("Error writing in file!");
            e.printStackTrace();
        }
    }

    /**
     * Reads a specific line from a file
     *
     * @param line number of the line to be read
     * @param path the path of the file to read
     *
     * @return line requested
     */
    public static String getLineFromFile(int line, String path, SecretKey key) throws Exception {
        String fileContent = new String(readFile(path));
        String[] lines = fileContent.split("\n");
        return Encryption.decrypt("AES",lines[line],key);
    }

    /**
     * Gets a specific info from a line from the file
     *
     * @param line line to get the text from
     * @param parameter position of info to get
     * @param path path to the file
     * @return info selected from the line
     */
    public static String getTextFromLine(int line, int parameter, String path, SecretKey key) throws Exception {
        String lineRead = getLineFromFile(line, path, key);
        String[] parameters = lineRead.split("/");
        return parameters[parameter];
    }

    /**
     * Edits a specific line from a file
     *
     * @param line line to be changed
     * @param newContent text that substitutes the current line
     * @param path path to the file
     */
    public static void editLineFromFile(int line, String newContent, String path, SecretKey key) throws Exception {
        String fileContent = new String(readFile(path));
        String[] lines = fileContent.split("\n");
        for(int i = 0; i < lines.length; i++){
            lines[i] = Encryption.decrypt("AES", lines[i], key);
        }
        lines[line] = newContent;
        fileContent = "";
        for (String s : lines) {
            s = Encryption.encrypt("AES", s, key);
            fileContent = fileContent.concat(s + "\n");
        }

        writeFile(path, fileContent.getBytes(),false);
    }

    /**
     * Edits a specific info from a line from a file
     *
     * @param line line that contains the info to be changed
     * @param parameter position of the info to be changed
     * @param newContent text that substitutes the current line
     * @param path path to the file
     */
    public static void editTextFromLine(int line, int parameter, String newContent, String path, SecretKey key) {
        try {
            String lineEdit = getLineFromFile(line, path, key);
            String[] parameters = lineEdit.split("/");
            parameters[parameter] = newContent;
            lineEdit = parameters[0] + "/" + parameters[1] + "/" + parameters[2];
            editLineFromFile(line, lineEdit, path, key);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Deletes the directory and all its files
     *
     * @param directoryToBeDeleted the directory to be deleted
     */
    public static void deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        directoryToBeDeleted.delete();
    }
}
