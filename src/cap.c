/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *    Description:  简单例程测试:客户端通过ONVIF协议搜索前端设备,
 *        Created:  2013年12月26日 12时17分48秒
 *       Compiler:  gcc
 *         Author:  max_min_,
 *
 * =====================================================================================
 */
#include "wsdd.h"
#include <stdio.h>
#include <ctype.h>
#include "cap.h"

static const char base64digits[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD     -1
static const signed char base64val[] = {
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
    52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
    15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
    BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
    41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
};
#define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)

void base64_bits_to_64(unsigned char *out, const unsigned char *in, int inlen)
{
    for (; inlen >= 3; inlen -= 3)
    {
        *out++ = base64digits[in[0] >> 2];
        *out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = base64digits[in[2] & 0x3f];
        in += 3;
    }

    if (inlen > 0)
    {
        unsigned char fragment;

        *out++ = base64digits[in[0] >> 2];
        fragment = (in[0] << 4) & 0x30;

        if (inlen > 1)
            fragment |= in[1] >> 4;

        *out++ = base64digits[fragment];
        *out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }

    *out = '\0';
}
int base64_64_to_bits(char *out, const char *in)
{
    int len = 0;
    register unsigned char digit1, digit2, digit3, digit4;

    if (in[0] == '+' && in[1] == ' ')
        in += 2;
    if (*in == '\r')
        return(0);

    do {
        digit1 = in[0];
        if (DECODE64(digit1) == BAD)
            return(-1);
        digit2 = in[1];
        if (DECODE64(digit2) == BAD)
            return(-1);
        digit3 = in[2];
        if (digit3 != '=' && DECODE64(digit3) == BAD)
            return(-1);
        digit4 = in[3];
        if (digit4 != '=' && DECODE64(digit4) == BAD)
            return(-1);
        in += 4;
        *out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
        ++len;
        if (digit3 != '=')
        {
            *out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
            ++len;
            if (digit4 != '=')
            {
                *out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
                ++len;
            }
        }
    } while (*in && *in != '\r' && digit4 != '=');

    return (len);
}


static void ONVIF_GenrateDigest(unsigned char *pwddigest_out, unsigned char *pwd, char *nonc, char *time)
{
    const unsigned char *tdist;
    unsigned char dist[1024] = {0};
    char tmp[1024] = {0};
    unsigned char bout[1024] = {0};
    strcpy(tmp,nonc);
    base64_64_to_bits((char*)bout, tmp);
    sprintf(tmp,"%s%s%s",bout,time,pwd);
    sha1((const unsigned char*)tmp,strlen((const char*)tmp),dist);
    tdist = dist;
    memset(bout,0x0,1024);
    base64_bits_to_64(bout,tdist,(int)strlen((const char*)tdist));
    strcpy((char *)pwddigest_out,(const char*)bout);
}
 //鉴权操作函数，以及上面的用到了openssl接口
static struct soap* ONVIF_Initsoap(struct SOAP_ENV__Header *header, const char *was_To, const char *was_Action, int timeout)
{
    struct soap *soap = NULL;
    unsigned char macaddr[6];
    char _HwId[1024];
    unsigned int Flagrand;
    soap = soap_new();
    if(soap == NULL)
    {
        printf("[%d]soap = NULL\n", __LINE__);
        return NULL;
    }
     soap_set_namespaces( soap, namespaces);
    //超过5秒钟没有数据就退出
    if (timeout > 0)
    {
        soap->recv_timeout = timeout;
        soap->send_timeout = timeout;
        soap->connect_timeout = timeout;
    }
    else
    {
        //如果外部接口没有设备默认超时时间的话，我这里给了一个默认值10s
        soap->recv_timeout    = 10;
        soap->send_timeout    = 10;
        soap->connect_timeout = 10;
    }
    soap_default_SOAP_ENV__Header(soap, header);

    // 为了保证每次搜索的时候MessageID都是不相同的！因为简单，直接取了随机值
    srand((int)time(0));
    Flagrand = rand()%9000 + 1000; //保证四位整数
    macaddr[0] = 0x1; macaddr[1] = 0x2; macaddr[2] = 0x3; macaddr[3] = 0x4; macaddr[4] = 0x5; macaddr[5] = 0x6;
    sprintf(_HwId,"urn:uuid:%ud68a-1dd2-11b2-a105-%02X%02X%02X%02X%02X%02X",
            Flagrand, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    header->wsa__MessageID =(char *)malloc( 100);
    memset(header->wsa__MessageID, 0, 100);
    strncpy(header->wsa__MessageID, _HwId, strlen(_HwId));

    if (was_Action != NULL)
    {
        header->wsa__Action =(char *)malloc(1024);
        memset(header->wsa__Action, '\0', 1024);
        strncpy(header->wsa__Action, was_Action, 1024);//"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    }
    if (was_To != NULL)
    {
        header->wsa__To =(char *)malloc(1024);
        memset(header->wsa__To, '\0', 1024);
        strncpy(header->wsa__To,  was_To, 1024);//"urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    }
    soap->header = header;
    return soap;
}


void ONVIF_ClientDiscovery(char *ServiceAddr)
{
    int HasDev = 0;
    int retval = SOAP_OK;
    wsdd__ProbeType req;
    struct __wsdd__ProbeMatches resp;
    wsdd__ScopesType sScope;
    struct SOAP_ENV__Header header;
    struct soap* soap;


    const char *was_To = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    const char *was_Action = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    //这个就是传递过去的组播的ip地址和对应的端口发送广播信息
    const char *soap_endpoint = "soap.udp://239.255.255.250:3702/";

    //这个接口填充一些信息并new返回一个soap对象，本来可以不用额外接口，
    // 但是后期会作其他操作，此部分剔除出来后面的操作就相对简单了,只是调用接口就好
    soap = ONVIF_Initsoap(&header, was_To, was_Action, 5);

    soap_default_SOAP_ENV__Header(soap, &header);
    soap->header = &header;

    soap_default_wsdd__ScopesType(soap, &sScope);
    sScope.__item = "";
    soap_default_wsdd__ProbeType(soap, &req);
    req.Scopes = &sScope;
    req.Types = ""; //"dn:NetworkVideoTransmitter";

    retval = soap_send___wsdd__Probe(soap, soap_endpoint, NULL, &req);
    //发送组播消息成功后，开始循环接收各位设备发送过来的消息
    while (retval == SOAP_OK)
    {
        retval = soap_recv___wsdd__ProbeMatches(soap, &resp);
        if (retval == SOAP_OK)
        {
            if (soap->error)
            {
                //printf("[%d]: recv soap error :%d, %s, %s\n", __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
            }
            else //成功接收某一个设备的消息
            {
                HasDev ++;
                if (resp.wsdd__ProbeMatches->ProbeMatch != NULL && resp.wsdd__ProbeMatches->ProbeMatch->XAddrs != NULL)
                {
                    //printf(" ################  recv  %d devices info #### \n", HasDev );
                    //printf("Target Service Address  : %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->XAddrs);
                    int len = strlen(resp.wsdd__ProbeMatches->ProbeMatch->XAddrs) + 1;
                    memcpy(ServiceAddr, resp.wsdd__ProbeMatches->ProbeMatch->XAddrs, len);
                    //printf("Target EP Address       : %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address);
                    //printf("Target Type             : %s\r\n", resp.wsdd__ProbeMatches->ProbeMatch->Types);
                    //printf("Target Metadata Version : %d\r\n", resp.wsdd__ProbeMatches->ProbeMatch->MetadataVersion);
                    //sleep(1);
                }
                break;
            }
        }
        else if (soap->error)
        {
            if (HasDev == 0)
            {
                //printf("[%s][%s][Line:%d] Thers Device discovery or soap error: %d, %s, %s \n",__FILE__, __func__, __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
            }
            else
            {
                //printf(" [%s]-[%d] Search end! It has Searched %d devices! \n", __func__, __LINE__, HasDev);
                retval = 0;
            }
            break;
        }
    }

    soap_destroy(soap);
    soap_end(soap);
    soap_free(soap);

    //return retval;
}


void ONVIF_Capabilities(char *rtsp_uri)  //获取设备能力接口
{

    int retval = 0;
    struct soap *soap = NULL;
    struct _tds__GetCapabilities capa_req;
    struct _tds__GetCapabilitiesResponse capa_resp;
    struct _trt__GetProfiles trt__GetProfiles;
    struct _trt__GetProfilesResponse trt__GetProfilesResponse;
    struct _trt__GetStreamUri trt__GetStreamUri;
    struct _trt__GetStreamUriResponse trt__GetStreamUriResponse;
    struct SOAP_ENV__Header header;

    soap = ONVIF_Initsoap(&header, NULL, NULL, 5);

    char *soap_endpoint = (char *)malloc(256);
    memset(soap_endpoint, 0, 256);
    //海康的设备，固定ip连接设备获取能力值 ,实际开发的时候，"172.18.14.22"地址以及80端口号需要填写在动态搜索到的具体信息
    //sprintf(soap_endpoint, "http://%s:%d/onvif/device_service", "192.168.1.201", 80);

    ONVIF_ClientDiscovery(soap_endpoint);

    capa_req.Category = (enum tt__CapabilityCategory *)soap_malloc(soap, sizeof(int));
    capa_req.__sizeCategory = 1;
    *(capa_req.Category) = (enum tt__CapabilityCategory)0;
    //此句也可以不要，因为在接口soap_call___tds__GetCapabilities中判断了，如果此值为NULL,则会给它赋值
    const char *soap_action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities";

    do
    {
        soap_call___tds__GetCapabilities(soap, soap_endpoint, soap_action, &capa_req, &capa_resp);
        if (soap->error)
        {
                printf("[%s][%d]--->>> soap error: %d, %s, %s\n", __func__, __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
                break;
        }
        else   //获取参数成功
        {
            // 走到这里的时候，已经就是验证成功了，可以获取到参数了，
            // 在实际开发的时候，可以把capa_resp结构体的那些需要的值匹配到自己的私有协议中去，简单的赋值操作就好
            printf("[%s][%d] Get capabilities success !\n", __func__, __LINE__);
            if (capa_resp.Capabilities == NULL)
            {
                printf("Get capabilities fialed!\n");
            }
            else
            {
                printf(" Media->XAddr=%s \n", capa_resp.Capabilities->Media->XAddr);
            }

            retval = soap_call___trt__GetProfiles(soap, capa_resp.Capabilities->Media->XAddr, NULL, &trt__GetProfiles, &trt__GetProfilesResponse);
            if (retval==-1)
              //NOTE: it may be regular if result isn't SOAP_OK.Because some attributes aren't supported by server.
              //any question email leoluopy@gmail.com
              {
                printf("soap error: %d, %s, %s\n", soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
                exit(-1);
              }
              else{
                printf("\n-------------------Profiles Get OK--------------\n\n");
                if(trt__GetProfilesResponse.Profiles!=NULL)
                {
                  if(trt__GetProfilesResponse.Profiles->Name!=NULL){
                    printf("Profiles Name:%s  \n",trt__GetProfilesResponse.Profiles->Name);

                  }
                  if(trt__GetProfilesResponse.Profiles->token!=NULL){
                    printf("Profiles Taken:%s\n",trt__GetProfilesResponse.Profiles->token);
                  }
                }
                else{
                  printf("Profiles Get inner Error\n");

                }
              }

            //printf("Profiles Get Procedure over\n");


            trt__GetStreamUri.StreamSetup = (struct tt__StreamSetup*)soap_malloc(soap,sizeof(struct tt__StreamSetup));//初始化，分配空间
              trt__GetStreamUri.StreamSetup->Stream = 0;//stream type

              trt__GetStreamUri.StreamSetup->Transport = (struct tt__Transport *)soap_malloc(soap, sizeof(struct tt__Transport));//初始化，分配空间
              trt__GetStreamUri.StreamSetup->Transport->Protocol = 0;
              trt__GetStreamUri.StreamSetup->Transport->Tunnel = 0;
              trt__GetStreamUri.StreamSetup->__size = 1;
              trt__GetStreamUri.StreamSetup->__any = NULL;
              trt__GetStreamUri.StreamSetup->__anyAttribute =NULL;


              trt__GetStreamUri.ProfileToken = trt__GetProfilesResponse.Profiles->token ;

              //printf("\n\n---------------Getting Uri----------------\n\n");

              //soap_wsse_add_UsernameTokenDigest(soap,"user", ONVIF_USER, ONVIF_PASSWORD);
              soap_call___trt__GetStreamUri(soap, capa_resp.Capabilities->Media->XAddr, NULL, &trt__GetStreamUri, &trt__GetStreamUriResponse);


              if (soap->error) {
              printf("soap error: %d, %s, %s\n", soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
              retval = soap->error;

              }
              else{
                //printf("!!!!NOTE: RTSP Addr Get Done is :%s \n",trt__GetStreamUriResponse.MediaUri->Uri);
                int len = strlen(trt__GetStreamUriResponse.MediaUri->Uri) + 1;
                memcpy(rtsp_uri, trt__GetStreamUriResponse.MediaUri->Uri, len);
              }





        }
    }while(0);

    free(soap_endpoint);
    soap_endpoint = NULL;
    soap_destroy(soap);
    return retval;
}
