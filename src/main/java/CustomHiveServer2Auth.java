import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;

import org.apache.hadoop.conf.Configuration;
import javax.security.sasl.AuthenticationException;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CustomHiveServer2Auth implements PasswdAuthenticationProvider {
    @Override
    public void Authenticate(String username,String password) throws AuthenticationException{
        boolean ok = false;
        String passMd5 = new MD5().md5(password);
        HiveConf hiveConf = new HiveConf();
        Configuration conf = new Configuration(hiveConf);
        String filePath = conf.get("hive.server2.custom.authentication.file");
        System.out.print("hive.server2.custom.authentication.file [" + filePath + "] ..");
        File file = new File(filePath);
        BufferedReader reader = null;
        try {
             reader = new BufferedReader(new FileReader(file));
             String tempString = null;
             while ((tempString = reader.readLine())!= null){
                 String[] datas = tempString.split(",", -1);
                 if (datas.length !=2){
                     continue;
                 }
                 if (datas[0].equals(username) && datas[1].equals(passMd5)){
                     ok=true;
                     break;
                 }
             }
             reader.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new AuthenticationException("read auth config file error, [" + filePath + "] ..", e);
        }finally {
            if (reader != null){
                try {
                    reader.close();
                }catch (IOException e1){

                }
            }
        }
        if (ok){
            System.out.print("user [" + username + "] auth check ok .. ");
        }else {
            System.out.print("user [" + username + "] auth check fail .. ");
            throw new AuthenticationException("user [" + username + "] auth check fail .. ");
        }
    }
}
//MD5加密
class MD5{
    private MessageDigest digest;
    private char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public MD5(){
        try {
             digest = MessageDigest.getInstance("MD5");
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException(e);
        }
    }

    public String md5(String str){
        byte[] buInput = str.getBytes();
        digest.reset();;
        digest.update(buInput);
        byte[] md = this.digest.digest();
        //把密文转换程十六进制的字符串形式
        int j = md.length;
        char strChar[] = new char[j * 2];
        int k = 0;
        for (int i = 0; i < j; i++) {
            byte byte0 = md[i];
            strChar[k++] = hexDigits[byte0 >>> 4 & 0xf];
            strChar[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(strChar);
    }
}
