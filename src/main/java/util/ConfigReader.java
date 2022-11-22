package util;

import crypto.PBEFileDecryption;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;


public class ConfigReader {

    //path - localizacao do ficheiro que vamos ler
    //target - elemento que estamos a procurar
    public static ByteArrayOutputStream read(String path, String target) throws Exception {
        try {
            Scanner scan = new Scanner(new FileInputStream(path));
            List<String> lines = new LinkedList<>();
            while(scan.hasNextLine()){
                lines.add(scan.nextLine());
            }
            scan.close();

            String aux = new StringBuilder(target).insert(0, "<").append(">").toString();
            int index = lines.indexOf(aux);
            if(index == -1){
                throw new Exception("target not found");
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            boolean finished = false;
            String[] line;
            for (int i = index+1; i < lines.size() && !finished; i++) {
                aux = lines.get(i);

                if(aux.contains(target)){
                    finished = true;
                }
                else{
                    byteArrayOutputStream.write(aux.getBytes());
                }
            }
            byteArrayOutputStream.close();
            return byteArrayOutputStream;
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Problems related with config file occurred!\n"+e.getMessage());
        }
    }

    public static ByteArrayOutputStream readMovie(String path, String target, String password) throws Exception {
        try {
            InputStream stream = new ByteArrayInputStream(PBEFileDecryption.decryptFiles(password, path).toByteArray());
            Scanner scan = new Scanner(stream);
            List<String> lines = new LinkedList<>();
            while(scan.hasNextLine()){
                lines.add(scan.nextLine());
            }
            String aux = new StringBuilder(target).insert(0, "<").append(">").toString();
            int index = lines.indexOf(aux);
            if(index == -1){
                scan.close();
                throw new Exception("target not found");
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            boolean finished = false;
            String[] line;
            for (int i = index+1; i < lines.size() && !finished; i++) {
                aux = lines.get(i);

                if(aux.contains(target)){
                    finished = true;
                }
                else{
                    line = aux.split(":");
                    aux = line[0].toUpperCase()+": "+line[1];

                    byteArrayOutputStream.write(aux.getBytes());
                    byteArrayOutputStream.write("\n".getBytes());
                }
            }
            byteArrayOutputStream.close();
            scan.close();
            return byteArrayOutputStream;
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Problems related with config file occurred!\n"+e.getMessage());
        }
    }
}
