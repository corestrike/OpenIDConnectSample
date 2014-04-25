package gr.corestrike;

/**
 * Created by corestrike on 14/04/24.
 */
import static spark.Spark.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.json.JsonParser;
import com.google.api.client.util.Base64;
import spark.Request;
import spark.Response;
import spark.Route;
import spark.template.freemarker.FreeMarkerRoute;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.JsonToken;

public class App {
    private static String CLIENT_ID = "";
    private static String CLIENT_SECRET = "";

    // OAuth2 Parameter
    private static final String SCOPE = "openid email";
    private static final String STATE = "security_token%3D138r5719ru3e1%26url%3Dhttp://localhost:4567/oauth";

    private static final String AUTHORIZATION_SERVER_URL = "https://accounts.google.com/o/oauth2/auth";
    private static final String REDIRECT_URL = "http://localhost:4567/oauth2callback";
    private static final String TOKEN_SERVER_URL = "https://accounts.google.com/o/oauth2/token";

    /** Global instance of the HTTP transport. */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    /** Global instance of the JSON factory. */
    static final JsonFactory JSON_FACTORY = new JacksonFactory();

    public static void main(String[] args){
        // indexページ
        get(new FreeMarkerRoute("/"){
            @Override
            public Object handle(Request req, Response res){
                Map<String, Object> attributes = new HashMap<>();
                return modelAndView(attributes, "index.ftl");
            }
        });

        // OpenID Connectのエントリー
        post(new Route("/oauth") {
           @Override
           public Object handle(Request req, Response res){
               String clientId = req.queryMap().get("client_id").value();
               String clientSecret = req.queryMap().get("client_secret").value();

               if(clientId.isEmpty() || clientSecret.isEmpty()){
                   res.status(400);
                   return "Bad Request!";
               }else{
                   setCLIENT_ID(clientId);
                   setCLIENT_SECRET(clientSecret);
                   String authUrl = getCodeUrl();
                   res.redirect(authUrl);
               }

               return null;
           }
        });

        // コールバックメソッド
        get(new FreeMarkerRoute("/oauth2callback") {
            @Override
            public Object handle(Request req, Response res){
                // 本来はここでstateチェックをする

                // Tokenを取得
                String code = req.queryMap("code").value();
                TokenResponse tr = getTokenUrl(code);

                String[] jwt = ((String)tr.get("id_token")).split("\\.");
                byte[] jwtHeader = Base64.decodeBase64(jwt[0]);
                byte[] jwtClaim = Base64.decodeBase64(jwt[1]);
                byte[] jwtSigniture = Base64.decodeBase64(jwt[2]);

                // 本来はここでSignを検証する

                Map<String, Object> attributes = new HashMap<>();
                attributes.put("accesstoken", tr.getAccessToken());
                attributes.put("refreshtoken", tr.getRefreshToken() == null ? "null" : tr.getRefreshToken());
                attributes.put("tokentype", tr.getTokenType());
                attributes.put("expire", tr.getExpiresInSeconds());
                attributes.put("jwtheader", new String(jwtHeader));
                attributes.put("jwtclaim", new String(jwtClaim));
                attributes.put("jwtsign", new String(jwtSigniture));

                try{
                    JsonParser jsonParser = JSON_FACTORY.createJsonParser(new String(jwtClaim));
                    while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
                        String name = jsonParser.getCurrentName();
                        if(name != null) {
                            jsonParser.nextToken();

                            switch (name){
                                case "iss":
                                    attributes.put("iss", jsonParser.getText());
                                    break;
                                case "sub":
                                    attributes.put("sub", jsonParser.getText());
                                    break;
                                case "azp":
                                    attributes.put("azp", jsonParser.getText());
                                    break;
                                case "email":
                                    attributes.put("email", jsonParser.getText());
                                    break;
                                case "at_hash":
                                    attributes.put("at_hash", jsonParser.getText());
                                    break;
                                case "email_verified":
                                    attributes.put("email_verified", jsonParser.getText());
                                    break;
                                case "aud":
                                    attributes.put("aud", jsonParser.getText());
                                    break;
                                case "iat":
                                    attributes.put("iat", jsonParser.getText());
                                    break;
                                case "exp":
                                    attributes.put("exp", jsonParser.getText());
                                    break;
                            }
                        }
                    }
                }catch (IOException e){
                    e.printStackTrace();
                }

                return modelAndView(attributes, "callback.ftl");
            }
        });
    }

    // Authorization Codeを取得するURLを生成
    private static String getCodeUrl() {
        AuthorizationCodeRequestUrl codeUrl = new AuthorizationCodeRequestUrl(AUTHORIZATION_SERVER_URL, CLIENT_ID);
        codeUrl.setScopes(Arrays.asList(SCOPE));
        codeUrl.setResponseTypes(Arrays.asList("code"));
        codeUrl.setRedirectUri(REDIRECT_URL);
        codeUrl.setState(STATE);

        /* RefreshTokenを返却する場合
        codeUrl.set("access_type", "offline");
        */

        return codeUrl.build();
    }

    // Authorization Codeを利用して、Tokenを取得
    private static TokenResponse getTokenUrl(String code) {
        AuthorizationCodeTokenRequest tokenUrl = new AuthorizationCodeTokenRequest(
                HTTP_TRANSPORT,
                JSON_FACTORY,
                new GenericUrl(TOKEN_SERVER_URL),
                code
        );
        tokenUrl.setGrantType("authorization_code");
        tokenUrl.setRedirectUri(REDIRECT_URL);
        tokenUrl.set("client_id", CLIENT_ID);
        tokenUrl.set("client_secret", CLIENT_SECRET);

        TokenResponse tr = null;
        try {
            tr = tokenUrl.execute();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return tr;
    }

    private static void setCLIENT_ID(String clientId){
        CLIENT_ID = clientId;
    }
    private static void setCLIENT_SECRET(String clientSecret){
        CLIENT_SECRET = clientSecret;
    }
}
