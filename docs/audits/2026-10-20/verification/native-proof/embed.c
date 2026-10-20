#include "quickjs.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static JSValue random_fill(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
 size_t off,len,bpe,buflen; JSValue buf=JS_GetTypedArrayBuffer(ctx,argv[0],&off,&len,&bpe);
 if(JS_IsException(buf))return buf;
 unsigned char *p=JS_GetArrayBuffer(ctx,&buflen,buf);
 if(!p||len>65536||off+len>buflen||RAND_bytes(p+off,len)!=1){JS_FreeValue(ctx,buf);return JS_ThrowTypeError(ctx,"random error");}
 JS_FreeValue(ctx,buf);return JS_DupValue(ctx,argv[0]);
}
static JSValue log_line(JSContext *ctx, JSValueConst self,int argc,JSValueConst *argv){const char *s=JS_ToCString(ctx,argv[0]);if(s){puts(s);JS_FreeCString(ctx,s);}return JS_UNDEFINED;}
int main(int argc,char**argv){
 if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");if(!f)return 2;fseek(f,0,SEEK_END);size_t n=ftell(f);rewind(f);char*s=malloc(n+1);if(fread(s,1,n,f)!=n)return 2;s[n]=0;fclose(f);
 JSRuntime*rt=JS_NewRuntime();JS_SetMemoryLimit(rt,128*1024*1024);JS_SetMaxStackSize(rt,2*1024*1024);JSContext*ctx=JS_NewContext(rt);JSValue g=JS_GetGlobalObject(ctx);JS_SetPropertyStr(ctx,g,"nativeRandom",JS_NewCFunction(ctx,random_fill,"nativeRandom",1));JS_SetPropertyStr(ctx,g,"print",JS_NewCFunction(ctx,log_line,"print",1));JS_FreeValue(ctx,g);
 JSValue r=JS_Eval(ctx,s,n,argv[1],JS_EVAL_TYPE_GLOBAL);int bad=JS_IsException(r);if(bad){JSValue e=JS_GetException(ctx);const char*t=JS_ToCString(ctx,e);fprintf(stderr,"%s\n",t);JS_FreeCString(ctx,t);JS_FreeValue(ctx,e);}JS_FreeValue(ctx,r);free(s);JS_FreeContext(ctx);JS_FreeRuntime(rt);return bad;
}
