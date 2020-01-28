/*
 *
 *   Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package id.ac.its.sso;



import org.apache.axiom.om.util.Base64;
import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.oltu.oauth2.common.OAuth;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class provides the implementation to use "Apis" {@link "https://github.com/OAuth-Apis/apis"} for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class OAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(OAuthClient.class);

    // We need to maintain a mapping between Consumer Key and id. To get details of a specific client,
    // we need to call client registration endpoint using id.
    Map<String, Long> nameIdMapping = new HashMap<String, Long>();

    

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param configuration Configuration as a {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     */
    private KeyManagerConfiguration configuration;
    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        this.configuration = configuration;
    }

    /**
     * This method will Register the client in Authorization Server.
     *
     * @param oauthAppRequest this object holds all parameters required to register an OAuth Client.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
    	OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();

        log.debug("Creating a new oAuthApp in Authorization Server");

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        String registrationEndpoint = config.getParameter(OAuthClientConstants.CLIENT_REG_ENDPOINT);
        HttpPost httpPost = new HttpPost(registrationEndpoint.trim());

        HttpClient httpClient = getHttpClient();

        BufferedReader reader = null;

        try {
            Gson gson = new Gson();
        	String grantTypes = gson.toJson(oauthAppRequest.getOAuthApplicationInfo().getParameter("grant_types"));
            String ClientName = oauthAppRequest.getOAuthApplicationInfo().getClientName();
            String callBackURL = oauthAppRequest.getOAuthApplicationInfo().getCallBackURL();
            String paramsJson = "{\"client_name\":\""+ClientName+"\",\"redirect_uri\":\""+callBackURL+"\",\"grant_types\":"+grantTypes+"}";
            httpPost.setEntity(new StringEntity(paramsJson, OAuthClientConstants.UTF_8));
            httpPost.setHeader(OAuthClientConstants.CONTENT_TYPE, OAuthClientConstants.APPLICATION_JSON_CONTENT_TYPE);

           
            HttpResponse response = httpClient.execute(httpPost);
            int responseCode = response.getStatusLine().getStatusCode();

            JSONObject parsedObject;
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OAuthClientConstants.UTF_8));

            if (HttpStatus.SC_CREATED == responseCode) {

                parsedObject = getParsedObjectByReader(reader);
                
                if (parsedObject != null) {
                    oAuthApplicationInfo = createOAuthAppfromResponse(parsedObject);

                    return oAuthApplicationInfo;
                }
            } else {
                handleException("Some thing wrong here while registering the new client " +
                                "HTTP Error response code is " + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oauthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        
        log.debug("Updating OAuth Client..");
        String consumerKey = oauthAppRequest.getOAuthApplicationInfo().getClientId();
        String callBackURL = oauthAppRequest.getOAuthApplicationInfo().getCallBackURL();
        Gson gson = new Gson();
        String grantTypes = gson.toJson(oauthAppRequest.getOAuthApplicationInfo().getParameter("grant_types"));
        
        String registrationUrl = configuration.getParameter(OAuthClientConstants.CLIENT_REG_ENDPOINT);
        String apiKey = Base64.encode(new String(configuration.getParameter(OAuthClientConstants.WSO2ClientId)+":"+configuration.getParameter(OAuthClientConstants.WSO2ClientSecret)).getBytes());
        BufferedReader reader = null;

        registrationUrl += "/" + consumerKey;

        HttpClient client = getHttpClient();
        try {
            HttpPut httpPut = new HttpPut(registrationUrl);
            String paramsJson = "{\"redirect_uri\":\""+callBackURL+"\",\"grant_types\":"+grantTypes+"}";
            httpPut.setEntity(new StringEntity(paramsJson, "UTF8"));
            httpPut.setHeader(OAuthClientConstants.CONTENT_TYPE, OAuthClientConstants.APPLICATION_JSON_CONTENT_TYPE);
            httpPut.addHeader(OAuthClientConstants.API_KEY_AUTH,apiKey);
            
            HttpResponse response = client.execute(httpPut);

            int responseCode = response.getStatusLine().getStatusCode();

            log.debug("Response Code from Server: " + responseCode);

            JSONObject parsedObject;

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OAuthClientConstants.UTF_8));

            if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {
                    return createOAuthAppfromResponse(parsedObject);
                } else {
                    handleException("ParseObject is empty. Can not return oAuthApplicationInfo.");
                }
            } else {
                handleException("Some thing wrong here when updating the Client for key." + oauthAppRequest
                        .getOAuthApplicationInfo().getClientId() + ". Error " + "code" + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Some thing wrong here when Updating a Client for key " + oauthAppRequest
                    .getOAuthApplicationInfo().getClientId(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            client.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {
        log.debug("Creating a new OAuth Client in Authorization Server..");

        Long id = nameIdMapping.get(consumerKey);

        String configURL = configuration.getParameter(OAuthClientConstants.CLIENT_REG_ENDPOINT);
        String apiKey = Base64.encode(new String(configuration.getParameter(OAuthClientConstants.WSO2ClientId)+":"+configuration.getParameter(OAuthClientConstants.WSO2ClientSecret)).getBytes());
        
        HttpClient client = getHttpClient();

        try {

            if (id != null) {
                configURL += "/" + consumerKey;
                HttpDelete httpDelete = new HttpDelete(configURL);
                httpDelete.addHeader(OAuthClientConstants.API_KEY_AUTH,apiKey);
                HttpResponse response = client.execute(httpDelete);
                int responseCode = response.getStatusLine().getStatusCode();
                if (log.isDebugEnabled()) {
                    log.debug("Delete application response code :  " + responseCode);
                }
                if (responseCode == HttpStatus.SC_OK ||
                    responseCode == HttpStatus.SC_NO_CONTENT) {
                    log.info("OAuth Client for consumer Id " + consumerKey + " has been successfully deleted");
                } else {
                    handleException("Problem occurred while deleting client for Consumer Key " + consumerKey);
                }
            }

        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {
    	HttpClient client = getHttpClient();
    	String apiKey = Base64.encode(new String(configuration.getParameter(OAuthClientConstants.WSO2ClientId)+":"+configuration.getParameter(OAuthClientConstants.WSO2ClientSecret)).getBytes());
        String registrationURL = configuration.getParameter(OAuthClientConstants.CLIENT_REG_ENDPOINT)+"/"+consumerKey;
        BufferedReader reader = null;

        try {
            HttpGet request = new HttpGet(registrationURL);
            request.addHeader(OAuthClientConstants.API_KEY_AUTH,apiKey);
            
            HttpResponse response = client.execute(request);

            int responseCode = response.getStatusLine().getStatusCode();
            Object parsedObject;

            HttpEntity entity = response.getEntity();

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                if (reader != null) {
                    parsedObject = parser.parse(reader);
                    if (parsedObject instanceof JSONArray) {
                        for (Object object : (JSONArray) parsedObject) {
                            JSONObject jsonObject = (JSONObject) object;
                            if ((jsonObject.get(OAuthClientConstants.CLIENT_ID)).equals
                                    (consumerKey)) {
                                return createOAuthAppfromResponse(jsonObject);
                            }
                        }
                    } else {
                        return createOAuthAppfromResponse((JSONObject) parsedObject);
                    }
                }

            } else {
                handleException("Something went wrong while retrieving client for consumer key " + consumerKey);
            }

        } catch (ParseException e) {
            handleException("Error while parsing response json.", e);
        } catch (IOException e) {
            handleException("Error while reading response body.", e);
        } finally {
            client.getConnectionManager().shutdown();
            IOUtils.closeQuietly(reader);
        }

        return null;
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
                                                                  AccessTokenRequest tokenRequest)
            throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {
        if (tokenRequest == null) {
            return null;
        }
        
        String clientId = tokenRequest.getClientId();
        String clientSecret = tokenRequest.getClientSecret();
        AccessTokenInfo accessTokenInfo = null;
        HttpPost httpTokenPost = null;

        if (clientId != null && clientSecret != null) {
            String tokenEp = configuration.getParameter(OAuthClientConstants.TOKEN_ENDPOINT);
            if (tokenEp != null) {
                HttpClient tokenEPClient = new DefaultHttpClient();

                httpTokenPost = new HttpPost(tokenEp);

                List<NameValuePair> params = new ArrayList<NameValuePair>();
                params.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, "client_credentials"));
                params.add(new BasicNameValuePair("client_id", clientId));
                params.add(new BasicNameValuePair("client_secret", clientSecret));

                HttpResponse tokenResponse = null;
                BufferedReader reader = null;
                int statusCode;
                try {
                    httpTokenPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
                    tokenResponse = tokenEPClient.execute(httpTokenPost);
                    statusCode = tokenResponse.getStatusLine().getStatusCode();
                    HttpEntity entity = tokenResponse.getEntity();
                    reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

                    if (statusCode == HttpStatus.SC_OK) {
                        JSONParser parser = new JSONParser();
                        if (reader != null) {
                            Object parsedObject = parser.parse(reader);
                            if (parsedObject instanceof JSONObject) {
                                JSONObject jsonObject = (JSONObject) parsedObject;
                                String accessToken = (String) jsonObject.get(OAuth.OAUTH_ACCESS_TOKEN);
                                Long validityPeriod = (Long) jsonObject.get("expires_in");
                                String[] scopes = new String[0];
                                if (jsonObject.get("scope") != null) {
                                    scopes = ((String) jsonObject.get("scope")).split(",");
                                }
                                if (accessToken != null) {
                                    accessTokenInfo = new AccessTokenInfo();
                                    accessTokenInfo.setAccessToken(accessToken);
                                    accessTokenInfo.setValidityPeriod(validityPeriod);
                                    accessTokenInfo.setTokenValid(true);
                                    accessTokenInfo.setScope(scopes);
                                    accessTokenInfo.setConsumerKey(clientId);
                                } else {
                                    log.warn("Access Token Null");
                                }
                            }
                        }

                    } else {
                        handleException("Something went wrong while generating the Access Token");
                    }
                } catch (IOException e) {
                    log.error("Exception occurred while generating token.", e);
                } catch (ParseException e) {
                    log.error("Error occurred while parsing the response.", e);
                }
            }

        } else {
            log.warn("Client Key or Secret not specified");
        }

        return accessTokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        String introspectionURL = config.getParameter(OAuthClientConstants.INTROSPECTION_URL);
        BufferedReader reader = null;

        try {
            HttpGet httpGet = new HttpGet(introspectionURL);
            HttpClient client = new DefaultHttpClient();
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            HttpResponse response = client.execute(httpGet);
            int responseCode = response.getStatusLine().getStatusCode();
            if (log.isDebugEnabled()) {
                log.debug("HTTP Response code : " + responseCode);
            }
            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));
            if (HttpStatus.SC_OK == responseCode) {
                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {
                	Map valueMap = parsedObject;
                	
                    if(valueMap.get("expires")==null) {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }
                	
                	
                    String clientId = (String) valueMap.get("client_id");
                    Long expiryTimeString = (Long) valueMap.get("expires");
                    
                    if (clientId == null || expiryTimeString == null) {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
                        return tokenInfo;
                    }
                    long currentTime = System.currentTimeMillis();
                    long expiryTime = expiryTimeString*1000;
                    if (expiryTime > currentTime) {
                        tokenInfo.setTokenValid(true);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setValidityPeriod(expiryTime - currentTime);
                        tokenInfo.setIssuedTime(currentTime);
                        tokenInfo.setEndUserName(OAuthClientConstants.END_USER_NAME);
                        String scopesRaw = (String) valueMap.get("scope");
                        tokenInfo.setScope(scopesRaw.split("\\s+"));
                        
                    } else {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }
                } else {
                    log.error("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            }
            else {
                log.error("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }

        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request  to OAuth Provider. " +
                            e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        }
        catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(reader);
        }

        return tokenInfo;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param appInfoRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {
        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param responseMap Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppfromResponse(Map responseMap) {

        OAuthApplicationInfo info = new OAuthApplicationInfo();
        Object clientId = responseMap.get(OAuthClientConstants.CLIENT_ID);
        info.setClientId((String) clientId);

        Object clientSecret = responseMap.get(OAuthClientConstants.CLIENT_SECRET);
        info.setClientSecret((String) clientSecret);
        
        Object scopes = responseMap.get(OAuthClientConstants.SCOPES);
        if (scopes != null) {
            info.addParameter("scopes", scopes);
        }
        
        Object grant_types = responseMap.get("grant_types");
        if (grant_types != null) {
            info.addParameter("grant_types", grant_types);
        }

        return info;
    }

    /**
     * This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }
}