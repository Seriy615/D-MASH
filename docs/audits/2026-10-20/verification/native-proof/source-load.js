globalThis.self=globalThis; globalThis.crypto={getRandomValues:nativeRandom};
class TextEncoder { encode(s){return Uint8Array.from(unescape(encodeURIComponent(String(s))),c=>c.charCodeAt(0));} }
class TextDecoder { decode(b){return decodeURIComponent(escape(String.fromCharCode(...new Uint8Array(b))));} }
const abc='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function btoa(s){let o='';for(let i=0;i<s.length;i+=3){const n=(s.charCodeAt(i)<<16)|((s.charCodeAt(i+1)||0)<<8)|(s.charCodeAt(i+2)||0);o+=abc[n>>>18]+abc[(n>>>12)&63]+(i+1<s.length?abc[(n>>>6)&63]:'=')+(i+2<s.length?abc[n&63]:'=');}return o;}
function atob(s){let o='',v=0,n=0;for(const c of s.replace(/=+$/,'')){v=(v<<6)|abc.indexOf(c);n+=6;if(n>=8){n-=8;o+=String.fromCharCode((v>>>n)&255);}}return o;}
!function(i){"use strict";var v=function(r){var t,n=new Float64Array(16);if(r)for(t=0;t<r.length;t++)n[t]=r[t];return n},h=function(){throw new Error("no PRNG")},o=new Uint8Array(16),n=new Uint8Array(32);n[0]=9;var s=v(),u=v([1]),p=v([56129,1]),c=v([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),y=v([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),e=v([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),a=v([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),l=v([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function f(r,t,n,e){r[t]=n>>24&255,r[t+1]=n>>16&255,r[t+2]=n>>8&255,r[t+3]=255&n,r[t+4]=e>>24&255,r[t+5]=e>>16&255,r[t+6]=e>>8&255,r[t+7]=255&e}function w(r,t,n,e,o){var i,h=0;for(i=0;i<o;i++)h|=r[t+i]^n[e+i];return(1&h-1>>>8)-1}function b(r,t,n,e){return w(r,t,n,e,16)}function g(r,t,n,e){return w(r,t,n,e,32)}function A(r,t,n,e){!function(r,t,n,e){for(var o,i=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,f=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,s=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,u=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,c=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,w=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,v=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,p=255&n[16]|(255&n[17])<<8|(255&n[18])<<16|(255&n[19])<<24,b=255&n[20]|(255&n[21])<<8|(255&n[22])<<16|(255&n[23])<<24,g=255&n[24]|(255&n[25])<<8|(255&n[26])<<16|(255&n[27])<<24,A=255&n[28]|(255&n[29])<<8|(255&n[30])<<16|(255&n[31])<<24,_=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,U=i,d=h,E=a,x=f,M=s,m=u,B=c,S=y,k=l,K=w,Y=v,L=p,T=b,z=g,R=A,P=_,N=0;N<20;N+=2)U^=(o=(T^=(o=(k^=(o=(M^=(o=U+T|0)<<7|o>>>25)+U|0)<<9|o>>>23)+M|0)<<13|o>>>19)+k|0)<<18|o>>>14,m^=(o=(d^=(o=(z^=(o=(K^=(o=m+d|0)<<7|o>>>25)+m|0)<<9|o>>>23)+K|0)<<13|o>>>19)+z|0)<<18|o>>>14,Y^=(o=(B^=(o=(E^=(o=(R^=(o=Y+B|0)<<7|o>>>25)+Y|0)<<9|o>>>23)+R|0)<<13|o>>>19)+E|0)<<18|o>>>14,P^=(o=(L^=(o=(S^=(o=(x^=(o=P+L|0)<<7|o>>>25)+P|0)<<9|o>>>23)+x|0)<<13|o>>>19)+S|0)<<18|o>>>14,U^=(o=(x^=(o=(E^=(o=(d^=(o=U+x|0)<<7|o>>>25)+U|0)<<9|o>>>23)+d|0)<<13|o>>>19)+E|0)<<18|o>>>14,m^=(o=(M^=(o=(S^=(o=(B^=(o=m+M|0)<<7|o>>>25)+m|0)<<9|o>>>23)+B|0)<<13|o>>>19)+S|0)<<18|o>>>14,Y^=(o=(K^=(o=(k^=(o=(L^=(o=Y+K|0)<<7|o>>>25)+Y|0)<<9|o>>>23)+L|0)<<13|o>>>19)+k|0)<<18|o>>>14,P^=(o=(R^=(o=(z^=(o=(T^=(o=P+R|0)<<7|o>>>25)+P|0)<<9|o>>>23)+T|0)<<13|o>>>19)+z|0)<<18|o>>>14;U=U+i|0,d=d+h|0,E=E+a|0,x=x+f|0,M=M+s|0,m=m+u|0,B=B+c|0,S=S+y|0,k=k+l|0,K=K+w|0,Y=Y+v|0,L=L+p|0,T=T+b|0,z=z+g|0,R=R+A|0,P=P+_|0,r[0]=U>>>0&255,r[1]=U>>>8&255,r[2]=U>>>16&255,r[3]=U>>>24&255,r[4]=d>>>0&255,r[5]=d>>>8&255,r[6]=d>>>16&255,r[7]=d>>>24&255,r[8]=E>>>0&255,r[9]=E>>>8&255,r[10]=E>>>16&255,r[11]=E>>>24&255,r[12]=x>>>0&255,r[13]=x>>>8&255,r[14]=x>>>16&255,r[15]=x>>>24&255,r[16]=M>>>0&255,r[17]=M>>>8&255,r[18]=M>>>16&255,r[19]=M>>>24&255,r[20]=m>>>0&255,r[21]=m>>>8&255,r[22]=m>>>16&255,r[23]=m>>>24&255,r[24]=B>>>0&255,r[25]=B>>>8&255,r[26]=B>>>16&255,r[27]=B>>>24&255,r[28]=S>>>0&255,r[29]=S>>>8&255,r[30]=S>>>16&255,r[31]=S>>>24&255,r[32]=k>>>0&255,r[33]=k>>>8&255,r[34]=k>>>16&255,r[35]=k>>>24&255,r[36]=K>>>0&255,r[37]=K>>>8&255,r[38]=K>>>16&255,r[39]=K>>>24&255,r[40]=Y>>>0&255,r[41]=Y>>>8&255,r[42]=Y>>>16&255,r[43]=Y>>>24&255,r[44]=L>>>0&255,r[45]=L>>>8&255,r[46]=L>>>16&255,r[47]=L>>>24&255,r[48]=T>>>0&255,r[49]=T>>>8&255,r[50]=T>>>16&255,r[51]=T>>>24&255,r[52]=z>>>0&255,r[53]=z>>>8&255,r[54]=z>>>16&255,r[55]=z>>>24&255,r[56]=R>>>0&255,r[57]=R>>>8&255,r[58]=R>>>16&255,r[59]=R>>>24&255,r[60]=P>>>0&255,r[61]=P>>>8&255,r[62]=P>>>16&255,r[63]=P>>>24&255}(r,t,n,e)}function _(r,t,n,e){!function(r,t,n,e){for(var o,i=255&e[0]|(255&e[1])<<8|(255&e[2])<<16|(255&e[3])<<24,h=255&n[0]|(255&n[1])<<8|(255&n[2])<<16|(255&n[3])<<24,a=255&n[4]|(255&n[5])<<8|(255&n[6])<<16|(255&n[7])<<24,f=255&n[8]|(255&n[9])<<8|(255&n[10])<<16|(255&n[11])<<24,s=255&n[12]|(255&n[13])<<8|(255&n[14])<<16|(255&n[15])<<24,u=255&e[4]|(255&e[5])<<8|(255&e[6])<<16|(255&e[7])<<24,c=255&t[0]|(255&t[1])<<8|(255&t[2])<<16|(255&t[3])<<24,y=255&t[4]|(255&t[5])<<8|(255&t[6])<<16|(255&t[7])<<24,l=255&t[8]|(255&t[9])<<8|(255&t[10])<<16|(255&t[11])<<24,w=255&t[12]|(255&t[13])<<8|(255&t[14])<<16|(255&t[15])<<24,v=255&e[8]|(255&e[9])<<8|(255&e[10])<<16|(255&e[11])<<24,p=255&n[16]|(255&n[17])<<8|(255&n[18])<<16|(255&n[19])<<24,b=255&n[20]|(255&n[21])<<8|(255&n[22])<<16|(255&n[23])<<24,g=255&n[24]|(255&n[25])<<8|(255&n[26])<<16|(255&n[27])<<24,A=255&n[28]|(255&n[29])<<8|(255&n[30])<<16|(255&n[31])<<24,_=255&e[12]|(255&e[13])<<8|(255&e[14])<<16|(255&e[15])<<24,U=0;U<20;U+=2)i^=(o=(b^=(o=(l^=(o=(s^=(o=i+b|0)<<7|o>>>25)+i|0)<<9|o>>>23)+s|0)<<13|o>>>19)+l|0)<<18|o>>>14,u^=(o=(h^=(o=(g^=(o=(w^=(o=u+h|0)<<7|o>>>25)+u|0)<<9|o>>>23)+w|0)<<13|o>>>19)+g|0)<<18|o>>>14,v^=(o=(c^=(o=(a^=(o=(A^=(o=v+c|0)<<7|o>>>25)+v|0)<<9|o>>>23)+A|0)<<13|o>>>19)+a|0)<<18|o>>>14,_^=(o=(p^=(o=(y^=(o=(f^=(o=_+p|0)<<7|o>>>25)+_|0)<<9|o>>>23)+f|0)<<13|o>>>19)+y|0)<<18|o>>>14,i^=(o=(f^=(o=(a^=(o=(h^=(o=i+f|0)<<7|o>>>25)+i|0)<<9|o>>>23)+h|0)<<13|o>>>19)+a|0)<<18|o>>>14,u^=(o=(s^=(o=(y^=(o=(c^=(o=u+s|0)<<7|o>>>25)+u|0)<<9|o>>>23)+c|0)<<13|o>>>19)+y|0)<<18|o>>>14,v^=(o=(w^=(o=(l^=(o=(p^=(o=v+w|0)<<7|o>>>25)+v|0)<<9|o>>>23)+p|0)<<13|o>>>19)+l|0)<<18|o>>>14,_^=(o=(A^=(o=(g^=(o=(b^=(o=_+A|0)<<7|o>>>25)+_|0)<<9|o>>>23)+b|0)<<13|o>>>19)+g|0)<<18|o>>>14;r[0]=i>>>0&255,r[1]=i>>>8&255,r[2]=i>>>16&255,r[3]=i>>>24&255,r[4]=u>>>0&255,r[5]=u>>>8&255,r[6]=u>>>16&255,r[7]=u>>>24&255,r[8]=v>>>0&255,r[9]=v>>>8&255,r[10]=v>>>16&255,r[11]=v>>>24&255,r[12]=_>>>0&255,r[13]=_>>>8&255,r[14]=_>>>16&255,r[15]=_>>>24&255,r[16]=c>>>0&255,r[17]=c>>>8&255,r[18]=c>>>16&255,r[19]=c>>>24&255,r[20]=y>>>0&255,r[21]=y>>>8&255,r[22]=y>>>16&255,r[23]=y>>>24&255,r[24]=l>>>0&255,r[25]=l>>>8&255,r[26]=l>>>16&255,r[27]=l>>>24&255,r[28]=w>>>0&255,r[29]=w>>>8&255,r[30]=w>>>16&255,r[31]=w>>>24&255}(r,t,n,e)}var U=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function d(r,t,n,e,o,i,h){var a,f,s=new Uint8Array(16),u=new Uint8Array(64);for(f=0;f<16;f++)s[f]=0;for(f=0;f<8;f++)s[f]=i[f];for(;64<=o;){for(A(u,s,h,U),f=0;f<64;f++)r[t+f]=n[e+f]^u[f];for(a=1,f=8;f<16;f++)a=a+(255&s[f])|0,s[f]=255&a,a>>>=8;o-=64,t+=64,e+=64}if(0<o)for(A(u,s,h,U),f=0;f<o;f++)r[t+f]=n[e+f]^u[f];return 0}function E(r,t,n,e,o){var i,h,a=new Uint8Array(16),f=new Uint8Array(64);for(h=0;h<16;h++)a[h]=0;for(h=0;h<8;h++)a[h]=e[h];for(;64<=n;){for(A(f,a,o,U),h=0;h<64;h++)r[t+h]=f[h];for(i=1,h=8;h<16;h++)i=i+(255&a[h])|0,a[h]=255&i,i>>>=8;n-=64,t+=64}if(0<n)for(A(f,a,o,U),h=0;h<n;h++)r[t+h]=f[h];return 0}function x(r,t,n,e,o){var i=new Uint8Array(32);_(i,e,o,U);for(var h=new Uint8Array(8),a=0;a<8;a++)h[a]=e[a+16];return E(r,t,n,h,i)}function M(r,t,n,e,o,i,h){var a=new Uint8Array(32);_(a,i,h,U);for(var f=new Uint8Array(8),s=0;s<8;s++)f[s]=i[s+16];return d(r,t,n,e,o,f,a)}var m=function(r){var t,n,e,o,i,h,a,f;this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.leftover=0,t=255&r[this.fin=0]|(255&r[1])<<8,this.r[0]=8191&t,n=255&r[2]|(255&r[3])<<8,this.r[1]=8191&(t>>>13|n<<3),e=255&r[4]|(255&r[5])<<8,this.r[2]=7939&(n>>>10|e<<6),o=255&r[6]|(255&r[7])<<8,this.r[3]=8191&(e>>>7|o<<9),i=255&r[8]|(255&r[9])<<8,this.r[4]=255&(o>>>4|i<<12),this.r[5]=i>>>1&8190,h=255&r[10]|(255&r[11])<<8,this.r[6]=8191&(i>>>14|h<<2),a=255&r[12]|(255&r[13])<<8,this.r[7]=8065&(h>>>11|a<<5),f=255&r[14]|(255&r[15])<<8,this.r[8]=8191&(a>>>8|f<<8),this.r[9]=f>>>5&127,this.pad[0]=255&r[16]|(255&r[17])<<8,this.pad[1]=255&r[18]|(255&r[19])<<8,this.pad[2]=255&r[20]|(255&r[21])<<8,this.pad[3]=255&r[22]|(255&r[23])<<8,this.pad[4]=255&r[24]|(255&r[25])<<8,this.pad[5]=255&r[26]|(255&r[27])<<8,this.pad[6]=255&r[28]|(255&r[29])<<8,this.pad[7]=255&r[30]|(255&r[31])<<8};function B(r,t,n,e,o,i){var h=new m(i);return h.update(n,e,o),h.finish(r,t),0}function S(r,t,n,e,o,i){var h=new Uint8Array(16);return B(h,0,n,e,o,i),b(r,t,h,0)}function k(r,t,n,e,o){var i;if(n<32)return-1;for(M(r,0,t,0,n,e,o),B(r,16,r,32,n-32,r),i=0;i<16;i++)r[i]=0;return 0}function K(r,t,n,e,o){var i,h=new Uint8Array(32);if(n<32)return-1;if(x(h,0,32,e,o),0!==S(t,16,t,32,n-32,h))return-1;for(M(r,0,t,0,n,e,o),i=0;i<32;i++)r[i]=0;return 0}function Y(r,t){var n;for(n=0;n<16;n++)r[n]=0|t[n]}function L(r){var t,n,e=1;for(t=0;t<16;t++)n=r[t]+e+65535,e=Math.floor(n/65536),r[t]=n-65536*e;r[0]+=e-1+37*(e-1)}function T(r,t,n){for(var e,o=~(n-1),i=0;i<16;i++)e=o&(r[i]^t[i]),r[i]^=e,t[i]^=e}function z(r,t){var n,e,o,i=v(),h=v();for(n=0;n<16;n++)h[n]=t[n];for(L(h),L(h),L(h),e=0;e<2;e++){for(i[0]=h[0]-65517,n=1;n<15;n++)i[n]=h[n]-65535-(i[n-1]>>16&1),i[n-1]&=65535;i[15]=h[15]-32767-(i[14]>>16&1),o=i[15]>>16&1,i[14]&=65535,T(h,i,1-o)}for(n=0;n<16;n++)r[2*n]=255&h[n],r[2*n+1]=h[n]>>8}function R(r,t){var n=new Uint8Array(32),e=new Uint8Array(32);return z(n,r),z(e,t),g(n,0,e,0)}function P(r){var t=new Uint8Array(32);return z(t,r),1&t[0]}function N(r,t){var n;for(n=0;n<16;n++)r[n]=t[2*n]+(t[2*n+1]<<8);r[15]&=32767}function O(r,t,n){for(var e=0;e<16;e++)r[e]=t[e]+n[e]}function C(r,t,n){for(var e=0;e<16;e++)r[e]=t[e]-n[e]}function F(r,t,n){var e,o,i=0,h=0,a=0,f=0,s=0,u=0,c=0,y=0,l=0,w=0,v=0,p=0,b=0,g=0,A=0,_=0,U=0,d=0,E=0,x=0,M=0,m=0,B=0,S=0,k=0,K=0,Y=0,L=0,T=0,z=0,R=0,P=n[0],N=n[1],O=n[2],C=n[3],F=n[4],I=n[5],Z=n[6],G=n[7],q=n[8],D=n[9],V=n[10],X=n[11],j=n[12],H=n[13],J=n[14],Q=n[15];i+=(e=t[0])*P,h+=e*N,a+=e*O,f+=e*C,s+=e*F,u+=e*I,c+=e*Z,y+=e*G,l+=e*q,w+=e*D,v+=e*V,p+=e*X,b+=e*j,g+=e*H,A+=e*J,_+=e*Q,h+=(e=t[1])*P,a+=e*N,f+=e*O,s+=e*C,u+=e*F,c+=e*I,y+=e*Z,l+=e*G,w+=e*q,v+=e*D,p+=e*V,b+=e*X,g+=e*j,A+=e*H,_+=e*J,U+=e*Q,a+=(e=t[2])*P,f+=e*N,s+=e*O,u+=e*C,c+=e*F,y+=e*I,l+=e*Z,w+=e*G,v+=e*q,p+=e*D,b+=e*V,g+=e*X,A+=e*j,_+=e*H,U+=e*J,d+=e*Q,f+=(e=t[3])*P,s+=e*N,u+=e*O,c+=e*C,y+=e*F,l+=e*I,w+=e*Z,v+=e*G,p+=e*q,b+=e*D,g+=e*V,A+=e*X,_+=e*j,U+=e*H,d+=e*J,E+=e*Q,s+=(e=t[4])*P,u+=e*N,c+=e*O,y+=e*C,l+=e*F,w+=e*I,v+=e*Z,p+=e*G,b+=e*q,g+=e*D,A+=e*V,_+=e*X,U+=e*j,d+=e*H,E+=e*J,x+=e*Q,u+=(e=t[5])*P,c+=e*N,y+=e*O,l+=e*C,w+=e*F,v+=e*I,p+=e*Z,b+=e*G,g+=e*q,A+=e*D,_+=e*V,U+=e*X,d+=e*j,E+=e*H,x+=e*J,M+=e*Q,c+=(e=t[6])*P,y+=e*N,l+=e*O,w+=e*C,v+=e*F,p+=e*I,b+=e*Z,g+=e*G,A+=e*q,_+=e*D,U+=e*V,d+=e*X,E+=e*j,x+=e*H,M+=e*J,m+=e*Q,y+=(e=t[7])*P,l+=e*N,w+=e*O,v+=e*C,p+=e*F,b+=e*I,g+=e*Z,A+=e*G,_+=e*q,U+=e*D,d+=e*V,E+=e*X,x+=e*j,M+=e*H,m+=e*J,B+=e*Q,l+=(e=t[8])*P,w+=e*N,v+=e*O,p+=e*C,b+=e*F,g+=e*I,A+=e*Z,_+=e*G,U+=e*q,d+=e*D,E+=e*V,x+=e*X,M+=e*j,m+=e*H,B+=e*J,S+=e*Q,w+=(e=t[9])*P,v+=e*N,p+=e*O,b+=e*C,g+=e*F,A+=e*I,_+=e*Z,U+=e*G,d+=e*q,E+=e*D,x+=e*V,M+=e*X,m+=e*j,B+=e*H,S+=e*J,k+=e*Q,v+=(e=t[10])*P,p+=e*N,b+=e*O,g+=e*C,A+=e*F,_+=e*I,U+=e*Z,d+=e*G,E+=e*q,x+=e*D,M+=e*V,m+=e*X,B+=e*j,S+=e*H,k+=e*J,K+=e*Q,p+=(e=t[11])*P,b+=e*N,g+=e*O,A+=e*C,_+=e*F,U+=e*I,d+=e*Z,E+=e*G,x+=e*q,M+=e*D,m+=e*V,B+=e*X,S+=e*j,k+=e*H,K+=e*J,Y+=e*Q,b+=(e=t[12])*P,g+=e*N,A+=e*O,_+=e*C,U+=e*F,d+=e*I,E+=e*Z,x+=e*G,M+=e*q,m+=e*D,B+=e*V,S+=e*X,k+=e*j,K+=e*H,Y+=e*J,L+=e*Q,g+=(e=t[13])*P,A+=e*N,_+=e*O,U+=e*C,d+=e*F,E+=e*I,x+=e*Z,M+=e*G,m+=e*q,B+=e*D,S+=e*V,k+=e*X,K+=e*j,Y+=e*H,L+=e*J,T+=e*Q,A+=(e=t[14])*P,_+=e*N,U+=e*O,d+=e*C,E+=e*F,x+=e*I,M+=e*Z,m+=e*G,B+=e*q,S+=e*D,k+=e*V,K+=e*X,Y+=e*j,L+=e*H,T+=e*J,z+=e*Q,_+=(e=t[15])*P,h+=38*(d+=e*O),a+=38*(E+=e*C),f+=38*(x+=e*F),s+=38*(M+=e*I),u+=38*(m+=e*Z),c+=38*(B+=e*G),y+=38*(S+=e*q),l+=38*(k+=e*D),w+=38*(K+=e*V),v+=38*(Y+=e*X),p+=38*(L+=e*j),b+=38*(T+=e*H),g+=38*(z+=e*J),A+=38*(R+=e*Q),i=(e=(i+=38*(U+=e*N))+(o=1)+65535)-65536*(o=Math.floor(e/65536)),h=(e=h+o+65535)-65536*(o=Math.floor(e/65536)),a=(e=a+o+65535)-65536*(o=Math.floor(e/65536)),f=(e=f+o+65535)-65536*(o=Math.floor(e/65536)),s=(e=s+o+65535)-65536*(o=Math.floor(e/65536)),u=(e=u+o+65535)-65536*(o=Math.floor(e/65536)),c=(e=c+o+65535)-65536*(o=Math.floor(e/65536)),y=(e=y+o+65535)-65536*(o=Math.floor(e/65536)),l=(e=l+o+65535)-65536*(o=Math.floor(e/65536)),w=(e=w+o+65535)-65536*(o=Math.floor(e/65536)),v=(e=v+o+65535)-65536*(o=Math.floor(e/65536)),p=(e=p+o+65535)-65536*(o=Math.floor(e/65536)),b=(e=b+o+65535)-65536*(o=Math.floor(e/65536)),g=(e=g+o+65535)-65536*(o=Math.floor(e/65536)),A=(e=A+o+65535)-65536*(o=Math.floor(e/65536)),_=(e=_+o+65535)-65536*(o=Math.floor(e/65536)),i=(e=(i+=o-1+37*(o-1))+(o=1)+65535)-65536*(o=Math.floor(e/65536)),h=(e=h+o+65535)-65536*(o=Math.floor(e/65536)),a=(e=a+o+65535)-65536*(o=Math.floor(e/65536)),f=(e=f+o+65535)-65536*(o=Math.floor(e/65536)),s=(e=s+o+65535)-65536*(o=Math.floor(e/65536)),u=(e=u+o+65535)-65536*(o=Math.floor(e/65536)),c=(e=c+o+65535)-65536*(o=Math.floor(e/65536)),y=(e=y+o+65535)-65536*(o=Math.floor(e/65536)),l=(e=l+o+65535)-65536*(o=Math.floor(e/65536)),w=(e=w+o+65535)-65536*(o=Math.floor(e/65536)),v=(e=v+o+65535)-65536*(o=Math.floor(e/65536)),p=(e=p+o+65535)-65536*(o=Math.floor(e/65536)),b=(e=b+o+65535)-65536*(o=Math.floor(e/65536)),g=(e=g+o+65535)-65536*(o=Math.floor(e/65536)),A=(e=A+o+65535)-65536*(o=Math.floor(e/65536)),_=(e=_+o+65535)-65536*(o=Math.floor(e/65536)),i+=o-1+37*(o-1),r[0]=i,r[1]=h,r[2]=a,r[3]=f,r[4]=s,r[5]=u,r[6]=c,r[7]=y,r[8]=l,r[9]=w,r[10]=v,r[11]=p,r[12]=b,r[13]=g,r[14]=A,r[15]=_}function I(r,t){F(r,t,t)}function Z(r,t){var n,e=v();for(n=0;n<16;n++)e[n]=t[n];for(n=253;0<=n;n--)I(e,e),2!==n&&4!==n&&F(e,e,t);for(n=0;n<16;n++)r[n]=e[n]}function G(r,t){var n,e=v();for(n=0;n<16;n++)e[n]=t[n];for(n=250;0<=n;n--)I(e,e),1!==n&&F(e,e,t);for(n=0;n<16;n++)r[n]=e[n]}function q(r,t,n){var e,o,i=new Uint8Array(32),h=new Float64Array(80),a=v(),f=v(),s=v(),u=v(),c=v(),y=v();for(o=0;o<31;o++)i[o]=t[o];for(i[31]=127&t[31]|64,i[0]&=248,N(h,n),o=0;o<16;o++)f[o]=h[o],u[o]=a[o]=s[o]=0;for(a[0]=u[0]=1,o=254;0<=o;--o)T(a,f,e=i[o>>>3]>>>(7&o)&1),T(s,u,e),O(c,a,s),C(a,a,s),O(s,f,u),C(f,f,u),I(u,c),I(y,a),F(a,s,a),F(s,f,c),O(c,a,s),C(a,a,s),I(f,a),C(s,u,y),F(a,s,p),O(a,a,u),F(s,s,a),F(a,u,y),F(u,f,h),I(f,c),T(a,f,e),T(s,u,e);for(o=0;o<16;o++)h[o+16]=a[o],h[o+32]=s[o],h[o+48]=f[o],h[o+64]=u[o];var l=h.subarray(32),w=h.subarray(16);return Z(l,l),F(w,w,l),z(r,w),0}function D(r,t){return q(r,t,n)}function V(r,t){return h(t,32),D(r,t)}function X(r,t,n){var e=new Uint8Array(32);return q(e,n,t),_(r,o,e,U)}m.prototype.blocks=function(r,t,n){for(var e,o,i,h,a,f,s,u,c,y,l,w,v,p,b,g,A,_,U,d=this.fin?0:2048,E=this.h[0],x=this.h[1],M=this.h[2],m=this.h[3],B=this.h[4],S=this.h[5],k=this.h[6],K=this.h[7],Y=this.h[8],L=this.h[9],T=this.r[0],z=this.r[1],R=this.r[2],P=this.r[3],N=this.r[4],O=this.r[5],C=this.r[6],F=this.r[7],I=this.r[8],Z=this.r[9];16<=n;)y=c=0,y+=(E+=8191&(e=255&r[t+0]|(255&r[t+1])<<8))*T,y+=(x+=8191&(e>>>13|(o=255&r[t+2]|(255&r[t+3])<<8)<<3))*(5*Z),y+=(M+=8191&(o>>>10|(i=255&r[t+4]|(255&r[t+5])<<8)<<6))*(5*I),y+=(m+=8191&(i>>>7|(h=255&r[t+6]|(255&r[t+7])<<8)<<9))*(5*F),c=(y+=(B+=8191&(h>>>4|(a=255&r[t+8]|(255&r[t+9])<<8)<<12))*(5*C))>>>13,y&=8191,y+=(S+=a>>>1&8191)*(5*O),y+=(k+=8191&(a>>>14|(f=255&r[t+10]|(255&r[t+11])<<8)<<2))*(5*N),y+=(K+=8191&(f>>>11|(s=255&r[t+12]|(255&r[t+13])<<8)<<5))*(5*P),y+=(Y+=8191&(s>>>8|(u=255&r[t+14]|(255&r[t+15])<<8)<<8))*(5*R),l=c+=(y+=(L+=u>>>5|d)*(5*z))>>>13,l+=E*z,l+=x*T,l+=M*(5*Z),l+=m*(5*I),c=(l+=B*(5*F))>>>13,l&=8191,l+=S*(5*C),l+=k*(5*O),l+=K*(5*N),l+=Y*(5*P),c+=(l+=L*(5*R))>>>13,l&=8191,w=c,w+=E*R,w+=x*z,w+=M*T,w+=m*(5*Z),c=(w+=B*(5*I))>>>13,w&=8191,w+=S*(5*F),w+=k*(5*C),w+=K*(5*O),w+=Y*(5*N),v=c+=(w+=L*(5*P))>>>13,v+=E*P,v+=x*R,v+=M*z,v+=m*T,c=(v+=B*(5*Z))>>>13,v&=8191,v+=S*(5*I),v+=k*(5*F),v+=K*(5*C),v+=Y*(5*O),p=c+=(v+=L*(5*N))>>>13,p+=E*N,p+=x*P,p+=M*R,p+=m*z,c=(p+=B*T)>>>13,p&=8191,p+=S*(5*Z),p+=k*(5*I),p+=K*(5*F),p+=Y*(5*C),b=c+=(p+=L*(5*O))>>>13,b+=E*O,b+=x*N,b+=M*P,b+=m*R,c=(b+=B*z)>>>13,b&=8191,b+=S*T,b+=k*(5*Z),b+=K*(5*I),b+=Y*(5*F),g=c+=(b+=L*(5*C))>>>13,g+=E*C,g+=x*O,g+=M*N,g+=m*P,c=(g+=B*R)>>>13,g&=8191,g+=S*z,g+=k*T,g+=K*(5*Z),g+=Y*(5*I),A=c+=(g+=L*(5*F))>>>13,A+=E*F,A+=x*C,A+=M*O,A+=m*N,c=(A+=B*P)>>>13,A&=8191,A+=S*R,A+=k*z,A+=K*T,A+=Y*(5*Z),_=c+=(A+=L*(5*I))>>>13,_+=E*I,_+=x*F,_+=M*C,_+=m*O,c=(_+=B*N)>>>13,_&=8191,_+=S*P,_+=k*R,_+=K*z,_+=Y*T,U=c+=(_+=L*(5*Z))>>>13,U+=E*Z,U+=x*I,U+=M*F,U+=m*C,c=(U+=B*O)>>>13,U&=8191,U+=S*N,U+=k*P,U+=K*R,U+=Y*z,E=y=8191&(c=(c=((c+=(U+=L*T)>>>13)<<2)+c|0)+(y&=8191)|0),x=l+=c>>>=13,M=w&=8191,m=v&=8191,B=p&=8191,S=b&=8191,k=g&=8191,K=A&=8191,Y=_&=8191,L=U&=8191,t+=16,n-=16;this.h[0]=E,this.h[1]=x,this.h[2]=M,this.h[3]=m,this.h[4]=B,this.h[5]=S,this.h[6]=k,this.h[7]=K,this.h[8]=Y,this.h[9]=L},m.prototype.finish=function(r,t){var n,e,o,i,h=new Uint16Array(10);if(this.leftover){for(i=this.leftover,this.buffer[i++]=1;i<16;i++)this.buffer[i]=0;this.fin=1,this.blocks(this.buffer,0,16)}for(n=this.h[1]>>>13,this.h[1]&=8191,i=2;i<10;i++)this.h[i]+=n,n=this.h[i]>>>13,this.h[i]&=8191;for(this.h[0]+=5*n,n=this.h[0]>>>13,this.h[0]&=8191,this.h[1]+=n,n=this.h[1]>>>13,this.h[1]&=8191,this.h[2]+=n,h[0]=this.h[0]+5,n=h[0]>>>13,h[0]&=8191,i=1;i<10;i++)h[i]=this.h[i]+n,n=h[i]>>>13,h[i]&=8191;for(h[9]-=8192,e=(1^n)-1,i=0;i<10;i++)h[i]&=e;for(e=~e,i=0;i<10;i++)this.h[i]=this.h[i]&e|h[i];for(this.h[0]=65535&(this.h[0]|this.h[1]<<13),this.h[1]=65535&(this.h[1]>>>3|this.h[2]<<10),this.h[2]=65535&(this.h[2]>>>6|this.h[3]<<7),this.h[3]=65535&(this.h[3]>>>9|this.h[4]<<4),this.h[4]=65535&(this.h[4]>>>12|this.h[5]<<1|this.h[6]<<14),this.h[5]=65535&(this.h[6]>>>2|this.h[7]<<11),this.h[6]=65535&(this.h[7]>>>5|this.h[8]<<8),this.h[7]=65535&(this.h[8]>>>8|this.h[9]<<5),o=this.h[0]+this.pad[0],this.h[0]=65535&o,i=1;i<8;i++)o=(this.h[i]+this.pad[i]|0)+(o>>>16)|0,this.h[i]=65535&o;r[t+0]=this.h[0]>>>0&255,r[t+1]=this.h[0]>>>8&255,r[t+2]=this.h[1]>>>0&255,r[t+3]=this.h[1]>>>8&255,r[t+4]=this.h[2]>>>0&255,r[t+5]=this.h[2]>>>8&255,r[t+6]=this.h[3]>>>0&255,r[t+7]=this.h[3]>>>8&255,r[t+8]=this.h[4]>>>0&255,r[t+9]=this.h[4]>>>8&255,r[t+10]=this.h[5]>>>0&255,r[t+11]=this.h[5]>>>8&255,r[t+12]=this.h[6]>>>0&255,r[t+13]=this.h[6]>>>8&255,r[t+14]=this.h[7]>>>0&255,r[t+15]=this.h[7]>>>8&255},m.prototype.update=function(r,t,n){var e,o;if(this.leftover){for(n<(o=16-this.leftover)&&(o=n),e=0;e<o;e++)this.buffer[this.leftover+e]=r[t+e];if(n-=o,t+=o,this.leftover+=o,this.leftover<16)return;this.blocks(this.buffer,0,16),this.leftover=0}if(16<=n&&(o=n-n%16,this.blocks(r,t,o),t+=o,n-=o),n){for(e=0;e<n;e++)this.buffer[this.leftover+e]=r[t+e];this.leftover+=n}};var j=k,H=K;var J=[1116352408,3609767458,1899447441,602891725,3049323471,3964484399,3921009573,2173295548,961987163,4081628472,1508970993,3053834265,2453635748,2937671579,2870763221,3664609560,3624381080,2734883394,310598401,1164996542,607225278,1323610764,1426881987,3590304994,1925078388,4068182383,2162078206,991336113,2614888103,633803317,3248222580,3479774868,3835390401,2666613458,4022224774,944711139,264347078,2341262773,604807628,2007800933,770255983,1495990901,1249150122,1856431235,1555081692,3175218132,1996064986,2198950837,2554220882,3999719339,2821834349,766784016,2952996808,2566594879,3210313671,3203337956,3336571891,1034457026,3584528711,2466948901,113926993,3758326383,338241895,168717936,666307205,1188179964,773529912,1546045734,1294757372,1522805485,1396182291,2643833823,1695183700,2343527390,1986661051,1014477480,2177026350,1206759142,2456956037,344077627,2730485921,1290863460,2820302411,3158454273,3259730800,3505952657,3345764771,106217008,3516065817,3606008344,3600352804,1432725776,4094571909,1467031594,275423344,851169720,430227734,3100823752,506948616,1363258195,659060556,3750685593,883997877,3785050280,958139571,3318307427,1322822218,3812723403,1537002063,2003034995,1747873779,3602036899,1955562222,1575990012,2024104815,1125592928,2227730452,2716904306,2361852424,442776044,2428436474,593698344,2756734187,3733110249,3204031479,2999351573,3329325298,3815920427,3391569614,3928383900,3515267271,566280711,3940187606,3454069534,4118630271,4000239992,116418474,1914138554,174292421,2731055270,289380356,3203993006,460393269,320620315,685471733,587496836,852142971,1086792851,1017036298,365543100,1126000580,2618297676,1288033470,3409855158,1501505948,4234509866,1607167915,987167468,1816402316,1246189591];function Q(r,t,n,e){for(var o,i,h,a,f,s,u,c,y,l,w,v,p,b,g,A,_,U,d,E,x,M,m,B,S=new Int32Array(16),k=new Int32Array(16),K=r[0],Y=r[1],L=r[2],T=r[3],z=r[4],R=r[5],P=r[6],N=r[7],O=t[0],C=t[1],F=t[2],I=t[3],Z=t[4],G=t[5],q=t[6],D=t[7],V=0;128<=e;){for(_=0;_<16;_++)U=8*_+V,S[_]=n[U+0]<<24|n[U+1]<<16|n[U+2]<<8|n[U+3],k[_]=n[U+4]<<24|n[U+5]<<16|n[U+6]<<8|n[U+7];for(_=0;_<80;_++)if(o=Y,i=L,h=T,c=C,y=F,l=I,x=65535&(E=D),M=E>>>16,m=65535&(d=N),B=d>>>16,x+=65535&(E=((w=Z)>>>14|(a=z)<<18)^(Z>>>18|z<<14)^(z>>>9|Z<<23)),M+=E>>>16,m+=65535&(d=(z>>>14|Z<<18)^(z>>>18|Z<<14)^(Z>>>9|z<<23)),B+=d>>>16,x+=65535&(E=Z&(v=G)^~Z&(p=q)),M+=E>>>16,m+=65535&(d=z&(f=R)^~z&(s=P)),B+=d>>>16,d=J[2*_],x+=65535&(E=J[2*_+1]),M+=E>>>16,m+=65535&d,B+=d>>>16,d=S[_%16],M+=(E=k[_%16])>>>16,m+=65535&d,B+=d>>>16,m+=(M+=(x+=65535&E)>>>16)>>>16,x=65535&(E=A=65535&x|M<<16),M=E>>>16,m=65535&(d=g=65535&m|(B+=m>>>16)<<16),B=d>>>16,x+=65535&(E=(O>>>28|K<<4)^(K>>>2|O<<30)^(K>>>7|O<<25)),M+=E>>>16,m+=65535&(d=(K>>>28|O<<4)^(O>>>2|K<<30)^(O>>>7|K<<25)),B+=d>>>16,M+=(E=O&C^O&F^C&F)>>>16,m+=65535&(d=K&Y^K&L^Y&L),B+=d>>>16,u=65535&(m+=(M+=(x+=65535&E)>>>16)>>>16)|(B+=m>>>16)<<16,b=65535&x|M<<16,x=65535&(E=l),M=E>>>16,m=65535&(d=h),B=d>>>16,M+=(E=A)>>>16,m+=65535&(d=g),B+=d>>>16,Y=K,L=o,T=i,z=h=65535&(m+=(M+=(x+=65535&E)>>>16)>>>16)|(B+=m>>>16)<<16,R=a,P=f,N=s,K=u,C=O,F=c,I=y,Z=l=65535&x|M<<16,G=w,q=v,D=p,O=b,_%16==15)for(U=0;U<16;U++)d=S[U],x=65535&(E=k[U]),M=E>>>16,m=65535&d,B=d>>>16,d=S[(U+9)%16],x+=65535&(E=k[(U+9)%16]),M+=E>>>16,m+=65535&d,B+=d>>>16,g=S[(U+1)%16],x+=65535&(E=((A=k[(U+1)%16])>>>1|g<<31)^(A>>>8|g<<24)^(A>>>7|g<<25)),M+=E>>>16,m+=65535&(d=(g>>>1|A<<31)^(g>>>8|A<<24)^g>>>7),B+=d>>>16,g=S[(U+14)%16],M+=(E=((A=k[(U+14)%16])>>>19|g<<13)^(g>>>29|A<<3)^(A>>>6|g<<26))>>>16,m+=65535&(d=(g>>>19|A<<13)^(A>>>29|g<<3)^g>>>6),B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,S[U]=65535&m|B<<16,k[U]=65535&x|M<<16;x=65535&(E=O),M=E>>>16,m=65535&(d=K),B=d>>>16,d=r[0],M+=(E=t[0])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[0]=K=65535&m|B<<16,t[0]=O=65535&x|M<<16,x=65535&(E=C),M=E>>>16,m=65535&(d=Y),B=d>>>16,d=r[1],M+=(E=t[1])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[1]=Y=65535&m|B<<16,t[1]=C=65535&x|M<<16,x=65535&(E=F),M=E>>>16,m=65535&(d=L),B=d>>>16,d=r[2],M+=(E=t[2])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[2]=L=65535&m|B<<16,t[2]=F=65535&x|M<<16,x=65535&(E=I),M=E>>>16,m=65535&(d=T),B=d>>>16,d=r[3],M+=(E=t[3])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[3]=T=65535&m|B<<16,t[3]=I=65535&x|M<<16,x=65535&(E=Z),M=E>>>16,m=65535&(d=z),B=d>>>16,d=r[4],M+=(E=t[4])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[4]=z=65535&m|B<<16,t[4]=Z=65535&x|M<<16,x=65535&(E=G),M=E>>>16,m=65535&(d=R),B=d>>>16,d=r[5],M+=(E=t[5])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[5]=R=65535&m|B<<16,t[5]=G=65535&x|M<<16,x=65535&(E=q),M=E>>>16,m=65535&(d=P),B=d>>>16,d=r[6],M+=(E=t[6])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[6]=P=65535&m|B<<16,t[6]=q=65535&x|M<<16,x=65535&(E=D),M=E>>>16,m=65535&(d=N),B=d>>>16,d=r[7],M+=(E=t[7])>>>16,m+=65535&d,B+=d>>>16,B+=(m+=(M+=(x+=65535&E)>>>16)>>>16)>>>16,r[7]=N=65535&m|B<<16,t[7]=D=65535&x|M<<16,V+=128,e-=128}return e}function W(r,t,n){var e,o=new Int32Array(8),i=new Int32Array(8),h=new Uint8Array(256),a=n;for(o[0]=1779033703,o[1]=3144134277,o[2]=1013904242,o[3]=2773480762,o[4]=1359893119,o[5]=2600822924,o[6]=528734635,o[7]=1541459225,i[0]=4089235720,i[1]=2227873595,i[2]=4271175723,i[3]=1595750129,i[4]=2917565137,i[5]=725511199,i[6]=4215389547,i[7]=327033209,Q(o,i,t,n),n%=128,e=0;e<n;e++)h[e]=t[a-n+e];for(h[n]=128,h[(n=256-128*(n<112?1:0))-9]=0,f(h,n-8,a/536870912|0,a<<3),Q(o,i,h,n),e=0;e<8;e++)f(r,8*e,o[e],i[e]);return 0}function $(r,t){var n=v(),e=v(),o=v(),i=v(),h=v(),a=v(),f=v(),s=v(),u=v();C(n,r[1],r[0]),C(u,t[1],t[0]),F(n,n,u),O(e,r[0],r[1]),O(u,t[0],t[1]),F(e,e,u),F(o,r[3],t[3]),F(o,o,y),F(i,r[2],t[2]),O(i,i,i),C(h,e,n),C(a,i,o),O(f,i,o),O(s,e,n),F(r[0],h,a),F(r[1],s,f),F(r[2],f,a),F(r[3],h,s)}function rr(r,t,n){var e;for(e=0;e<4;e++)T(r[e],t[e],n)}function tr(r,t){var n=v(),e=v(),o=v();Z(o,t[2]),F(n,t[0],o),F(e,t[1],o),z(r,e),r[31]^=P(n)<<7}function nr(r,t,n){var e,o;for(Y(r[0],s),Y(r[1],u),Y(r[2],u),Y(r[3],s),o=255;0<=o;--o)rr(r,t,e=n[o/8|0]>>(7&o)&1),$(t,r),$(r,r),rr(r,t,e)}function er(r,t){var n=[v(),v(),v(),v()];Y(n[0],e),Y(n[1],a),Y(n[2],u),F(n[3],e,a),nr(r,n,t)}function or(r,t,n){var e,o=new Uint8Array(64),i=[v(),v(),v(),v()];for(n||h(t,32),W(o,t,32),o[0]&=248,o[31]&=127,o[31]|=64,er(i,o),tr(r,i),e=0;e<32;e++)t[e+32]=r[e];return 0}var ir=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function hr(r,t){var n,e,o,i;for(e=63;32<=e;--e){for(n=0,o=e-32,i=e-12;o<i;++o)t[o]+=n-16*t[e]*ir[o-(e-32)],n=Math.floor((t[o]+128)/256),t[o]-=256*n;t[o]+=n,t[e]=0}for(o=n=0;o<32;o++)t[o]+=n-(t[31]>>4)*ir[o],n=t[o]>>8,t[o]&=255;for(o=0;o<32;o++)t[o]-=n*ir[o];for(e=0;e<32;e++)t[e+1]+=t[e]>>8,r[e]=255&t[e]}function ar(r){var t,n=new Float64Array(64);for(t=0;t<64;t++)n[t]=r[t];for(t=0;t<64;t++)r[t]=0;hr(r,n)}function fr(r,t,n,e){var o,i,h=new Uint8Array(64),a=new Uint8Array(64),f=new Uint8Array(64),s=new Float64Array(64),u=[v(),v(),v(),v()];W(h,e,32),h[0]&=248,h[31]&=127,h[31]|=64;var c=n+64;for(o=0;o<n;o++)r[64+o]=t[o];for(o=0;o<32;o++)r[32+o]=h[32+o];for(W(f,r.subarray(32),n+32),ar(f),er(u,f),tr(r,u),o=32;o<64;o++)r[o]=e[o];for(W(a,r,n+64),ar(a),o=0;o<64;o++)s[o]=0;for(o=0;o<32;o++)s[o]=f[o];for(o=0;o<32;o++)for(i=0;i<32;i++)s[o+i]+=a[o]*h[i];return hr(r.subarray(32),s),c}function sr(r,t,n,e){var o,i=new Uint8Array(32),h=new Uint8Array(64),a=[v(),v(),v(),v()],f=[v(),v(),v(),v()];if(n<64)return-1;if(function(r,t){var n=v(),e=v(),o=v(),i=v(),h=v(),a=v(),f=v();if(Y(r[2],u),N(r[1],t),I(o,r[1]),F(i,o,c),C(o,o,r[2]),O(i,r[2],i),I(h,i),I(a,h),F(f,a,h),F(n,f,o),F(n,n,i),G(n,n),F(n,n,o),F(n,n,i),F(n,n,i),F(r[0],n,i),I(e,r[0]),F(e,e,i),R(e,o)&&F(r[0],r[0],l),I(e,r[0]),F(e,e,i),R(e,o))return 1;P(r[0])===t[31]>>7&&C(r[0],s,r[0]),F(r[3],r[0],r[1])}(f,e))return-1;for(o=0;o<n;o++)r[o]=t[o];for(o=0;o<32;o++)r[o+32]=e[o];if(W(h,r,n),ar(h),nr(a,f,h),er(f,t.subarray(32)),$(a,f),tr(i,a),n-=64,g(t,0,i,0)){for(o=0;o<n;o++)r[o]=0;return-1}for(o=0;o<n;o++)r[o]=t[o+64];return n}function ur(r,t){if(32!==r.length)throw new Error("bad key size");if(24!==t.length)throw new Error("bad nonce size")}function cr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function yr(r){for(var t=0;t<r.length;t++)r[t]=0}i.lowlevel={crypto_core_hsalsa20:_,crypto_stream_xor:M,crypto_stream:x,crypto_stream_salsa20_xor:d,crypto_stream_salsa20:E,crypto_onetimeauth:B,crypto_onetimeauth_verify:S,crypto_verify_16:b,crypto_verify_32:g,crypto_secretbox:k,crypto_secretbox_open:K,crypto_scalarmult:q,crypto_scalarmult_base:D,crypto_box_beforenm:X,crypto_box_afternm:j,crypto_box:function(r,t,n,e,o,i){var h=new Uint8Array(32);return X(h,o,i),j(r,t,n,e,h)},crypto_box_open:function(r,t,n,e,o,i){var h=new Uint8Array(32);return X(h,o,i),H(r,t,n,e,h)},crypto_box_keypair:V,crypto_hash:W,crypto_sign:fr,crypto_sign_keypair:or,crypto_sign_open:sr,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:16,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:64,crypto_sign_PUBLICKEYBYTES:32,crypto_sign_SECRETKEYBYTES:64,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:v,D:c,L:ir,pack25519:z,unpack25519:N,M:F,A:O,S:I,Z:C,pow2523:G,add:$,set25519:Y,modL:hr,scalarmult:nr,scalarbase:er},i.randomBytes=function(r){var t=new Uint8Array(r);return h(t,r),t},i.secretbox=function(r,t,n){cr(r,t,n),ur(n,t);for(var e=new Uint8Array(32+r.length),o=new Uint8Array(e.length),i=0;i<r.length;i++)e[i+32]=r[i];return k(o,e,e.length,t,n),o.subarray(16)},i.secretbox.open=function(r,t,n){cr(r,t,n),ur(n,t);for(var e=new Uint8Array(16+r.length),o=new Uint8Array(e.length),i=0;i<r.length;i++)e[i+16]=r[i];return e.length<32||0!==K(o,e,e.length,t,n)?null:o.subarray(32)},i.secretbox.keyLength=32,i.secretbox.nonceLength=24,i.secretbox.overheadLength=16,i.scalarMult=function(r,t){if(cr(r,t),32!==r.length)throw new Error("bad n size");if(32!==t.length)throw new Error("bad p size");var n=new Uint8Array(32);return q(n,r,t),n},i.scalarMult.base=function(r){if(cr(r),32!==r.length)throw new Error("bad n size");var t=new Uint8Array(32);return D(t,r),t},i.scalarMult.scalarLength=32,i.scalarMult.groupElementLength=32,i.box=function(r,t,n,e){var o=i.box.before(n,e);return i.secretbox(r,t,o)},i.box.before=function(r,t){cr(r,t),function(r,t){if(32!==r.length)throw new Error("bad public key size");if(32!==t.length)throw new Error("bad secret key size")}(r,t);var n=new Uint8Array(32);return X(n,r,t),n},i.box.after=i.secretbox,i.box.open=function(r,t,n,e){var o=i.box.before(n,e);return i.secretbox.open(r,t,o)},i.box.open.after=i.secretbox.open,i.box.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(32);return V(r,t),{publicKey:r,secretKey:t}},i.box.keyPair.fromSecretKey=function(r){if(cr(r),32!==r.length)throw new Error("bad secret key size");var t=new Uint8Array(32);return D(t,r),{publicKey:t,secretKey:new Uint8Array(r)}},i.box.publicKeyLength=32,i.box.secretKeyLength=32,i.box.sharedKeyLength=32,i.box.nonceLength=24,i.box.overheadLength=i.secretbox.overheadLength,i.sign=function(r,t){if(cr(r,t),64!==t.length)throw new Error("bad secret key size");var n=new Uint8Array(64+r.length);return fr(n,r,r.length,t),n},i.sign.open=function(r,t){if(cr(r,t),32!==t.length)throw new Error("bad public key size");var n=new Uint8Array(r.length),e=sr(n,r,r.length,t);if(e<0)return null;for(var o=new Uint8Array(e),i=0;i<o.length;i++)o[i]=n[i];return o},i.sign.detached=function(r,t){for(var n=i.sign(r,t),e=new Uint8Array(64),o=0;o<e.length;o++)e[o]=n[o];return e},i.sign.detached.verify=function(r,t,n){if(cr(r,t,n),64!==t.length)throw new Error("bad signature size");if(32!==n.length)throw new Error("bad public key size");var e,o=new Uint8Array(64+r.length),i=new Uint8Array(64+r.length);for(e=0;e<64;e++)o[e]=t[e];for(e=0;e<r.length;e++)o[e+64]=r[e];return 0<=sr(i,o,o.length,n)},i.sign.keyPair=function(){var r=new Uint8Array(32),t=new Uint8Array(64);return or(r,t),{publicKey:r,secretKey:t}},i.sign.keyPair.fromSecretKey=function(r){if(cr(r),64!==r.length)throw new Error("bad secret key size");for(var t=new Uint8Array(32),n=0;n<t.length;n++)t[n]=r[32+n];return{publicKey:t,secretKey:new Uint8Array(r)}},i.sign.keyPair.fromSeed=function(r){if(cr(r),32!==r.length)throw new Error("bad seed size");for(var t=new Uint8Array(32),n=new Uint8Array(64),e=0;e<32;e++)n[e]=r[e];return or(t,n,!0),{publicKey:t,secretKey:n}},i.sign.publicKeyLength=32,i.sign.secretKeyLength=64,i.sign.seedLength=32,i.sign.signatureLength=64,i.hash=function(r){cr(r);var t=new Uint8Array(64);return W(t,r,r.length),t},i.hash.hashLength=64,i.verify=function(r,t){return cr(r,t),0!==r.length&&0!==t.length&&(r.length===t.length&&0===w(r,0,t,0,r.length))},i.setPRNG=function(r){h=r},function(){var o="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(o&&o.getRandomValues){i.setPRNG(function(r,t){var n,e=new Uint8Array(t);for(n=0;n<t;n+=65536)o.getRandomValues(e.subarray(n,n+Math.min(t-n,65536)));for(n=0;n<t;n++)r[n]=e[n];yr(e)})}else"undefined"!=typeof require&&(o=require("crypto"))&&o.randomBytes&&i.setPRNG(function(r,t){var n,e=o.randomBytes(t);for(n=0;n<t;n++)r[n]=e[n];yr(e)})}()}("undefined"!=typeof module&&module.exports?module.exports:self.nacl=self.nacl||{});
var DmashBlake3=(()=>{var D=Object.defineProperty;var rt=Object.getOwnPropertyDescriptor;var ot=Object.getOwnPropertyNames;var it=Object.prototype.hasOwnProperty;var ht=(e,n,t)=>n in e?D(e,n,{enumerable:!0,configurable:!0,writable:!0,value:t}):e[n]=t;var ft=(e,n)=>{for(var t in n)D(e,t,{get:n[t],enumerable:!0})},ct=(e,n,t,o)=>{if(n&&typeof n=="object"||typeof n=="function")for(let r of ot(n))!it.call(e,r)&&r!==t&&D(e,r,{get:()=>n[r],enumerable:!(o=rt(n,r))||o.enumerable});return e};var ut=e=>ct(D({},"__esModule",{value:!0}),e);var l=(e,n,t)=>ht(e,typeof n!="symbol"?n+"":n,t);var dt={};ft(dt,{blake3:()=>st});var M=e=>e/2**32|0,P=e=>e>>>0;function q(e){return e instanceof Uint8Array||ArrayBuffer.isView(e)&&e.constructor.name==="Uint8Array"&&"BYTES_PER_ELEMENT"in e&&e.BYTES_PER_ELEMENT===1}var $=e=>e?`"${e}" `:"";function T(e,n=""){if(typeof e!="number")throw new TypeError($(n)+"expected number, got "+typeof e);if(!Number.isSafeInteger(e)||e<0)throw new RangeError($(n)+"expected integer >= 0, got "+e);return e}function v(e,n,t=""){if(q(e)&&(n===void 0||e.length===n))return e;n!==void 0&&T(n,"length");let o=q(e),r=n!==void 0?` of length ${n}`:"",i=o?`length=${e.length}`:`type=${typeof e}`,s=$(t)+"expected Uint8Array"+r+", got "+i;throw o?new RangeError(s):new TypeError(s)}function K(e){return Uint8Array.from(v(e))}var lt=(e,n)=>{if(e===null||typeof e!="object"||Array.isArray(e))throw new TypeError((n==="object"?"":`"${n}" `)+"expected object, got type="+typeof e)},J=(e,n)=>{lt(e,n);let t=Object.getPrototypeOf(e);if(t!==Object.prototype&&t!==null)throw new TypeError(`"${n}" expected plain object`);if(Object.hasOwn(e,"__proto__"))throw new TypeError(`"${n}.__proto__" is not allowed`)};function B(e,n=!0){if(e.destroyed)throw new Error("hash was destroyed");if(n&&e.finished)throw new Error("digest() was already called")}function j(e,n){v(e,void 0,"output");let t=n.outputLen;if(!(e.length>=t))throw new RangeError('"output" expected length >= '+t)}function Q(e){return new Uint8Array(e.buffer,e.byteOffset,e.byteLength)}function H(e){return new Uint32Array(e.buffer,e.byteOffset,Math.floor(e.byteLength/4))}function U(...e){for(let n=0;n<e.length;n++)e[n].fill(0)}function V(e,n){return e<<32-n|e>>>n}var W=new Uint8Array(new Uint32Array([287454020]).buffer)[0]===68;function Z(e){return e<<24&4278190080|e<<8&16711680|e>>>8&65280|e>>>24&255}var tt=W?e=>e:e=>Z(e)>>>0;function at(e){for(let n=0;n<e.length;n++)e[n]=Z(e[n]);return e}var b=W?e=>e:at;function X(e,n,t="opts"){return J(e,"defaults"),n!==void 0&&J(n,t),Object.assign(Object.create(null),e,n)}function G(e,n={}){if(typeof e!="function")throw new TypeError('"hashCons" expected function, got type='+typeof e);n=X({},n,"info");let t=(r,i)=>e(i).update(r).digest(),o=e(void 0);return t.outputLen=o.outputLen,t.blockLen=o.blockLen,t.canXOF=o.canXOF,t.create=r=>e(r),Object.assign(t,n),Object.freeze(t)}var et=Uint32Array.from([1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225]);function I(e,n,t,o,r){return e=e+n+r|0,o=V(o^e,16),t=t+o|0,n=V(n^t,12),{a:e,b:n,c:t,d:o}}function L(e,n,t,o,r){return e=e+n+r|0,o=V(o^e,8),t=t+o|0,n=V(n^t,7),{a:e,b:n,c:t,d:o}}var F=class{constructor(n,t){l(this,"buffer");l(this,"buffer32");l(this,"finished",!1);l(this,"destroyed",!1);l(this,"length",0);l(this,"pos",0);l(this,"blockLen");l(this,"outputLen");l(this,"canXOF",!1);T(n),T(t),this.blockLen=n,this.outputLen=t,this.buffer=new Uint8Array(n),this.buffer32=H(this.buffer)}update(n){B(this),v(n);let{blockLen:t,buffer:o,buffer32:r}=this,i=n.length,s=n.byteOffset,f=n.buffer;for(let h=0;h<i;){this.pos===t&&(b(r),this.compress(r,0,!1),b(r),this.pos=0);let u=Math.min(t-this.pos,i-h),c=s+h;if(u===t&&!(c%4)&&h+u<i){let d=new Uint32Array(f,c,Math.floor((i-h)/4));b(d);for(let p=0;h+t<i;p+=r.length,h+=t)this.length+=t,this.compress(d,p,!1);b(d);continue}o.set(h===0&&u===i?n:n.subarray(h,h+u),this.pos),this.pos+=u,this.length+=u,h+=u}return this}digestInto(n){if(B(this),j(n,this),n.byteOffset&3)throw new RangeError('"output" expected 4-byte aligned byteOffset, got '+n.byteOffset);let{pos:t,buffer32:o}=this;this.finished=!0,this.buffer.fill(0,t),b(o),this.compress(o,0,!0),b(o);let r=this.get(),i=n===this.buffer?o:H(n),s=Math.floor(this.outputLen/4);for(let c=0;c<s;c++)i[c]=tt(r[c]);let f=this.outputLen%4;if(!f)return;let h=s*4,u=r[s];for(let c=0;c<f;c++)n[h+c]=u>>>8*c}digest(){let{buffer:n,outputLen:t}=this;this.digestInto(n);let o=n.slice(0,t);return this.destroy(),o}_cloneInto(n){let{buffer:t,length:o,finished:r,destroyed:i,outputLen:s,pos:f}=this;return n||(n=new this.constructor({dkLen:s})),n.set(...this.get()),n.buffer.set(t),n.destroyed=i,n.finished=r,n.length=o,n.pos=f,n.outputLen=s,n}clone(){return this._cloneInto()}};function Y(e,n,t,o,r,i,s,f,h,u,c,d,p,g,k,m,E,O,x,y){let a=0;for(let _=0;_<o;_++)({a:r,b:h,c:p,d:E}=I(r,h,p,E,t[n+e[a++]])),{a:r,b:h,c:p,d:E}=L(r,h,p,E,t[n+e[a++]]),{a:i,b:u,c:g,d:O}=I(i,u,g,O,t[n+e[a++]]),{a:i,b:u,c:g,d:O}=L(i,u,g,O,t[n+e[a++]]),{a:s,b:c,c:k,d:x}=I(s,c,k,x,t[n+e[a++]]),{a:s,b:c,c:k,d:x}=L(s,c,k,x,t[n+e[a++]]),{a:f,b:d,c:m,d:y}=I(f,d,m,y,t[n+e[a++]]),{a:f,b:d,c:m,d:y}=L(f,d,m,y,t[n+e[a++]]),{a:r,b:u,c:k,d:y}=I(r,u,k,y,t[n+e[a++]]),{a:r,b:u,c:k,d:y}=L(r,u,k,y,t[n+e[a++]]),{a:i,b:c,c:m,d:E}=I(i,c,m,E,t[n+e[a++]]),{a:i,b:c,c:m,d:E}=L(i,c,m,E,t[n+e[a++]]),{a:s,b:d,c:p,d:O}=I(s,d,p,O,t[n+e[a++]]),{a:s,b:d,c:p,d:O}=L(s,d,p,O,t[n+e[a++]]),{a:f,b:h,c:g,d:x}=I(f,h,g,x,t[n+e[a++]]),{a:f,b:h,c:g,d:x}=L(f,h,g,x,t[n+e[a++]]);return{v0:r,v1:i,v2:s,v3:f,v4:h,v5:u,v6:c,v7:d,v8:p,v9:g,v10:k,v11:m,v12:E,v13:O,v14:x,v15:y}}var A={CHUNK_START:1,CHUNK_END:2,PARENT:4,ROOT:8,KEYED_HASH:16,DERIVE_KEY_CONTEXT:32,DERIVE_KEY_MATERIAL:64},w=et.slice(),nt=(()=>{let e=Array.from({length:16},(o,r)=>r),n=o=>[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8].map(r=>o[r]),t=[];for(let o=0,r=e;o<7;o++,r=n(r))t.push(...r);return Uint8Array.from(t)})(),z=class e extends F{constructor(t={},o=0){t=X({},t);super(64,t.dkLen===void 0?32:t.dkLen);l(this,"canXOF",!0);l(this,"chunkPos",0);l(this,"chunksDone",0);l(this,"flags",0);l(this,"IV");l(this,"state");l(this,"stack",[]);l(this,"posOut",0);l(this,"bufferOut32",new Uint32Array(16));l(this,"bufferOut");l(this,"chunkOut",0);l(this,"enableXOF",!0);let{key:r,context:i}=t,s=i!==void 0;if(r!==void 0){if(s)throw new Error('cannot use both "key" and "context"');v(r,32,"key");let f=K(r);this.IV=H(f),b(this.IV),this.flags=o|A.KEYED_HASH}else if(s){v(i,void 0,"context");let f=i,h=new e({dkLen:32},A.DERIVE_KEY_CONTEXT).update(f).digest();this.IV=H(h),b(this.IV),this.flags=o|A.DERIVE_KEY_MATERIAL}else this.IV=w,this.flags=o;this.state=this.IV.slice(),this.bufferOut=Q(this.bufferOut32)}get(){return[]}set(){}b2Compress(t,o,r,i=0){let{state:s,pos:f}=this,h=P(t),u=M(t),{v0:c,v1:d,v2:p,v3:g,v4:k,v5:m,v6:E,v7:O,v8:x,v9:y,v10:a,v11:_,v12:S,v13:N,v14:R,v15:C}=Y(nt,i,r,7,s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],w[0],w[1],w[2],w[3],h,u,f,o);s[0]=c^x,s[1]=d^y,s[2]=p^a,s[3]=g^_,s[4]=k^S,s[5]=m^N,s[6]=E^R,s[7]=O^C}compress(t,o=0,r=!1){let i=this.flags;if(this.chunkPos||(i|=A.CHUNK_START),(this.chunkPos===15||r)&&(i|=A.CHUNK_END),r||(this.pos=this.blockLen),this.b2Compress(this.chunksDone,i,t,o),this.chunkPos+=1,this.chunkPos===16||r){let s=this.state;this.state=this.IV.slice();for(let f,h=this.chunksDone+1;(r||!(h&1))&&(f=this.stack.pop());h=Math.floor(h/2))this.buffer32.set(f,0),this.buffer32.set(s,8),this.pos=this.blockLen,this.b2Compress(0,this.flags|A.PARENT,this.buffer32,0),s=this.state,this.state=this.IV.slice();this.chunksDone++,this.chunkPos=0,this.stack.push(s)}this.pos=0}_cloneInto(t){let o=!!t&&t.finished&&!t.destroyed;t=super._cloneInto(t);let{IV:r,flags:i,state:s,chunkPos:f,posOut:h,chunkOut:u,stack:c,chunksDone:d}=this;return t.state.set(s),t.stack=c.map(p=>Uint32Array.from(p)),r===w?(t.IV!==w&&U(t.IV),t.IV=w):t.IV===w?t.IV=r.slice():t.IV.set(r),t.flags=i,t.chunkPos=f,t.chunksDone=d,t.posOut=h,t.chunkOut=u,t.enableXOF=this.enableXOF,this.finished?t.bufferOut32.set(this.bufferOut32):o&&U(t.bufferOut32),t}destroy(){this.destroyed=!0,U(this.state,this.buffer32,this.bufferOut32),this.IV!==w&&U(this.IV),U(...this.stack)}b2CompressOut(){let{state:t,pos:o,flags:r,buffer32:i,bufferOut32:s}=this,f=this.chunkOut++,h=P(f),u=M(f);b(i);let{v0:c,v1:d,v2:p,v3:g,v4:k,v5:m,v6:E,v7:O,v8:x,v9:y,v10:a,v11:_,v12:S,v13:N,v14:R,v15:C}=Y(nt,0,i,7,t[0],t[1],t[2],t[3],t[4],t[5],t[6],t[7],w[0],w[1],w[2],w[3],h,u,o,r);s[0]=c^x,s[1]=d^y,s[2]=p^a,s[3]=g^_,s[4]=k^S,s[5]=m^N,s[6]=E^R,s[7]=O^C,s[8]=t[0]^x,s[9]=t[1]^y,s[10]=t[2]^a,s[11]=t[3]^_,s[12]=t[4]^S,s[13]=t[5]^N,s[14]=t[6]^R,s[15]=t[7]^C,b(i),b(s),this.posOut=0}finish(){if(this.finished)return;this.finished=!0,this.buffer.fill(0,this.pos);let t=this.flags|A.ROOT;this.stack.length?(t|=A.PARENT,b(this.buffer32),this.compress(this.buffer32,0,!0),b(this.buffer32),this.chunksDone=0,this.pos=this.blockLen):t|=(this.chunkPos?0:A.CHUNK_START)|A.CHUNK_END,this.flags=t,this.b2CompressOut()}writeInto(t){B(this,!1),v(t),this.finish();let{blockLen:o,bufferOut:r}=this;for(let i=0,s=t.length;i<s;){this.posOut>=o&&this.b2CompressOut();let f=Math.min(o-this.posOut,s-i);t.set(r.subarray(this.posOut,this.posOut+f),i),this.posOut+=f,i+=f}return t}xofInto(t){if(!this.enableXOF)throw new Error("no XOF after digest()");return this.writeInto(t)}xof(t){return T(t),this.xofInto(new Uint8Array(t))}digestInto(t){if(j(t,this),this.finished)throw new Error("digest() was already called");this.enableXOF=!1,this.writeInto(t.length===this.outputLen?t:t.subarray(0,this.outputLen)),this.destroy()}digest(){let t=new Uint8Array(this.outputLen);return this.digestInto(t),t}},st=G((e={})=>new z(e));return ut(dt);})();
if (typeof module !== "undefined") module.exports = DmashBlake3;

"use strict";

// Shared explicitly selected v3/v4 cryptographic layer; does not grant Device or Node operations by itself.
(function (global) {
    const SUITE = "X25519-HKDF-SHA256-XSALSA20POLY1305";
    const domain = version => {
        if (![3, 4].includes(version)) throw new Error("Incompatible protocol version");
        return `D-MASH|DMP-C|${version}|`;
    };
    const validRole = (role, version) => {
        domain(version);
        if (!(version === 4 ? ["NODE"] : ["DEVICE", "NODE"]).includes(role)) throw new Error("Invalid role for protocol version");
    };
    const MAX_RECORD_BYTES = 1024 * 1024;
    const text = value => new TextEncoder().encode(value);
    const join = (...parts) => {
        const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let offset = 0;
        for (const part of parts) { result.set(part, offset); offset += part.length; }
        return result;
    };
    const b64 = bytes => {
        let value = "";
        for (let i = 0; i < bytes.length; i += 8192) value += String.fromCharCode(...bytes.subarray(i, i + 8192));
        return btoa(value);
    };
    const unb64 = (value, length) => {
        if (typeof value !== "string") throw new Error("Invalid encoding");
        const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
        if (b64(bytes) !== value || (length !== undefined && bytes.length !== length)) throw new Error("Invalid encoding");
        return bytes;
    };
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const unhex = value => {
        if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("Invalid identity");
        return Uint8Array.from(value.match(/../g), b => parseInt(b, 16));
    };
    function canonical(value, depth = 0) {
        if (depth > 32) throw new Error("Payload nesting limit");
        if (value === null || typeof value === "boolean") return JSON.stringify(value);
        if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
        if (typeof value === "string") return JSON.stringify(value).replace(/[\u0080-\uffff]/g, c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
        if (Array.isArray(value)) return "[" + value.map(v => canonical(v, depth + 1)).join(",") + "]";
        if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
            const keys = Object.keys(value).sort();
            if (keys.some(k => /[^\x00-\x7f]/.test(k))) throw new Error("ASCII object keys required");
            return "{" + keys.map(k => canonical(k) + ":" + canonical(value[k], depth + 1)).join(",") + "}";
        }
        throw new Error("Unsupported canonical value");
    }
    const digest = async bytes => new Uint8Array(await global.crypto.subtle.digest("SHA-256", bytes));
    async function hkdf(ikm, salt, info, length) {
        const key = await global.crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
        return new Uint8Array(await global.crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
    }
    const nonce = sequence => {
        const bytes = new Uint8Array(24);
        new DataView(bytes.buffer).setBigUint64(16, BigInt(sequence));
        return bytes;
    };
    class Session {
        constructor(sendKey, receiveKey, transcriptHash, {version = 3, localRole = "DEVICE", peerRole = "NODE", localId = null, peerId = null} = {}) {
            validRole(localRole, version); validRole(peerRole, version);
            this.version = version; this.localRole = localRole; this.peerRole = peerRole;
            this.localId = localId; this.peerId = peerId;
            this.sendKey = new Uint8Array(sendKey); this.receiveKey = new Uint8Array(receiveKey);
            this.transcriptHash = transcriptHash;
            this.sendSequence = 0; this.receiveSequence = 0; this.closed = false;
        }
        seal(payload) {
            if (this.closed || this.sendSequence > 0xffffffff) throw new Error("Session closed or exhausted");
            if (!payload || Array.isArray(payload) || typeof payload !== "object") throw new Error("Object payload required");
            const raw = text(canonical(payload));
            if (raw.length > MAX_RECORD_BYTES) throw new Error("Record too large");
            const sequence = this.sendSequence;
            const ciphertext = global.nacl.secretbox(raw, nonce(sequence), this.sendKey);
            this.sendSequence++;
            return { type: "SECURE", version: this.version, sequence, ciphertext: b64(ciphertext) };
        }
        open(frame) {
            if (this.closed) throw new Error("Session closed");
            try {
                if (!frame || Object.keys(frame).sort().join(",") !== "ciphertext,sequence,type,version" ||
                    frame.type !== "SECURE" || frame.version !== this.version || !Number.isSafeInteger(frame.sequence) ||
                    frame.sequence !== this.receiveSequence || frame.sequence > 0xffffffff ||
                    typeof frame.ciphertext !== "string" || frame.ciphertext.length > Math.floor((MAX_RECORD_BYTES + 18) / 3) * 4) throw new Error("Invalid record");
                const raw = global.nacl.secretbox.open(unb64(frame.ciphertext), nonce(frame.sequence), this.receiveKey);
                if (!raw || raw.length > MAX_RECORD_BYTES) throw new Error("Invalid ciphertext");
                const wire = new TextDecoder("utf-8", { fatal: true }).decode(raw);
                const payload = JSON.parse(wire);
                if (!payload || Array.isArray(payload) || typeof payload !== "object" || canonical(payload) !== wire) throw new Error("Invalid payload");
                this.receiveSequence++;
                return payload;
            } catch (error) { this.close(); throw error; }
        }
        close() { this.sendKey.fill(0); this.receiveKey.fill(0); this.closed = true; }
    }
    class Initiator {
        constructor(signing, role = "DEVICE", version = 3) {
            validRole(role, version);
            this.version = version; this.domain = domain(version);
            this.signing = signing; this.role = role;
            this.private = global.crypto.getRandomValues(new Uint8Array(32));
            this.used = false;
        }
        initiate() {
            if (this.used || this.hello) throw new Error("Handshake already used");
            this.hello = { type: "HELLO", protocol: "DMP-C", version: this.version, suite: SUITE,
                role: this.role, public_key: hex(this.signing.publicKey),
                ephemeral: b64(global.nacl.scalarMult.base(this.private)),
                nonce: b64(global.crypto.getRandomValues(new Uint8Array(32))) };
            return { ...this.hello };
        }
        async finish(response, expectedNodeId, now = Math.floor(Date.now() / 1000)) {
            if (this.used || !this.hello) throw new Error("Invalid handshake state");
            this.used = true;
            try {
                const challenge = { ...response }, signature = unb64(challenge.signature, 64);
                delete challenge.signature;
                if (Object.keys(challenge).sort().join(",") !== "ephemeral,expires_at,nonce,peer_role,protocol,public_key,role,suite,type,version" ||
                    challenge.type !== "CHALLENGE" || challenge.protocol !== "DMP-C" || challenge.version !== this.version ||
                    challenge.suite !== SUITE || challenge.role !== "NODE" || challenge.peer_role !== this.role ||
                    challenge.public_key !== expectedNodeId || !Number.isSafeInteger(challenge.expires_at) ||
                    // Allow small clock skew when the Node issues its 15s
                    // challenge. The Node still enforces its original deadline;
                    // expired challenges and all signature checks stay strict.
                    challenge.expires_at <= now || challenge.expires_at > now + 20) throw new Error("Invalid challenge");
                const nodeKey = unhex(expectedNodeId);
                unb64(challenge.nonce, 32);
                const ephemeral = unb64(challenge.ephemeral, 32);
                const hash = await digest(join(text(this.domain + "HANDSHAKE\0"), text(canonical([this.hello, challenge]))));
                if (!global.nacl.sign.detached.verify(join(text(this.domain + "RESPONDER\0"), hash), signature, nodeKey)) throw new Error("Node signature failed");
                const auth = { type: "AUTH", version: this.version, signature: b64(global.nacl.sign.detached(join(text(this.domain + "INITIATOR\0"), hash), this.signing.secretKey)) };
                const shared = global.nacl.scalarMult(this.private, ephemeral);
                if (!shared.some(b => b !== 0)) throw new Error("Invalid shared secret");
                const ikm = join(text("X25519\0"), new Uint8Array([0, 0, 0, 32]), shared);
                let keys;
                try { keys = await hkdf(ikm, hash, text(this.domain + SUITE), 64); }
                finally { shared.fill(0); ikm.fill(0); }
                try { return { auth, session: new Session(keys.subarray(0, 32), keys.subarray(32), hash, {version: this.version, localRole: this.role, peerRole: "NODE", localId: this.hello.public_key, peerId: challenge.public_key}) }; }
                finally { keys.fill(0); }
            } finally { this.close(); }
        }
        close() { this.private.fill(0); this.signing = null; this.used = true; }
    }
    global.DmashSecureSession = { Initiator, Session, canonical, b64, unb64, hkdf, SUITE };
    if (typeof module !== "undefined") module.exports = global.DmashSecureSession;
})(typeof window !== "undefined" ? window : globalThis);

'use strict';
// Node identity work is identical for every runtime: BLAKE3(lowercase Ed25519
// public-key hex) starts with 0520. Account keys are never inputs here.
(function (global) {
    const PREFIX = '0520';
    const MAX_MINING_MS = 15 * 60 * 1000;
    const scriptUrl = global.document?.currentScript?.src || global.DMASH_NODE_WORKER_URLS?.identity;
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    const hash = value => hex(global.DmashBlake3.blake3(new TextEncoder().encode(value)));
    const verify = nodeId => typeof nodeId === 'string' && /^[0-9a-f]{64}$/.test(nodeId) && hash(nodeId).startsWith(PREFIX);
    let active = null;
    function mine({signal, timeoutMs = MAX_MINING_MS} = {}) {
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_MINING_MS) return Promise.reject(Error('Invalid mining deadline'));
        if (signal?.aborted) return Promise.reject(Error('Node identity mining cancelled'));
        if (active) return Promise.reject(Error('Node identity miner busy'));
        if (!global.Worker || !scriptUrl) return Promise.reject(Error('Node identity mining requires a Worker'));
        return new Promise((resolve, reject) => {
            const worker = new global.Worker(scriptUrl);
            active = worker;
            let finished = false;
            const finish = (error, seed) => {
                if (finished) { seed?.fill(0); return; }
                finished = true;
                clearTimeout(timer);
                signal?.removeEventListener('abort', cancel);
                worker.terminate();
                if (active === worker) active = null;
                if (error) { seed?.fill(0); reject(error); } else resolve(seed);
            };
            const cancel = () => finish(Error('Node identity mining cancelled'));
            const timer = setTimeout(() => finish(Error('Node identity mining expired')), timeoutMs);
            signal?.addEventListener('abort', cancel, {once:true});
            worker.onerror = () => finish(Error('Node identity Worker failed'));
            worker.onmessage = ({data}) => {
                if (data?.type === 'EXPIRED') { finish(Error('Node identity mining expired')); return; }
                const seed = data?.seed;
                if (data?.type !== 'NODE_IDENTITY' || !(seed instanceof Uint8Array) || seed.length !== 32) {
                    finish(Error('Invalid Node identity result'), seed instanceof Uint8Array ? seed : undefined); return;
                }
                let signing;
                try {
                    signing = global.nacl.sign.keyPair.fromSeed(seed);
                    if (!verify(hex(signing.publicKey))) throw Error('Node identity work rejected');
                    finish(null, seed);
                } catch (error) { finish(error, seed); }
                finally { signing?.secretKey.fill(0); }
            };
            worker.postMessage({type:'MINE_NODE_IDENTITY', timeoutMs});
        });
    }
    async function unlockDeviceIdentity(deviceRoot, options = {}) {
        const session = deviceRoot?.state;
        if (!session?.root || typeof deviceRoot.deviceMaterial !== 'function') throw Error('Device must be unlocked');
        let seed, signing;
        try {
            // Independent random seed behind the installation root; never derive
            // from an Account or reuse the older DEVICE signing identity.
            seed = await deviceRoot.deviceMaterial('node-ed25519-pow-v4', () => mine(options));
            if (deviceRoot.state !== session || options.signal?.aborted) throw Error('Device session changed');
            if (!(seed instanceof Uint8Array) || seed.length !== 32) throw Error('Invalid persisted Node identity');
            signing = global.nacl.sign.keyPair.fromSeed(seed);
            const nodeId = hex(signing.publicKey);
            if (!verify(nodeId)) throw Error('Persisted Node identity work rejected');
            return Object.freeze({nodeId, signing});
        } catch (error) {
            signing?.secretKey.fill(0);
            throw error;
        } finally { seed?.fill(0); }
    }
    if (typeof WorkerGlobalScope !== 'undefined' && global instanceof WorkerGlobalScope) {
        importScripts('vendor/nacl-fast.min.js', 'vendor/blake3.min.js');
        let mining = false;
        global.onmessage = async ({data}) => {
            if (mining || data?.type !== 'MINE_NODE_IDENTITY' || !Number.isInteger(data.timeoutMs) || data.timeoutMs < 1 || data.timeoutMs > MAX_MINING_MS) {
                global.postMessage({type:'ERROR'}); return;
            }
            mining = true;
            const deadline = Date.now() + data.timeoutMs;
            try {
                // Native Ed25519 avoids repeating the much slower JS public
                // key derivation for every rejected candidate. Same identity
                // distribution and unchanged BLAKE3 work threshold.
                let nativeKeys = null, native = true;
                try { nativeKeys = await global.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']); }
                catch (_) { native = false; }
                while (Date.now() < deadline) {
                    if (native) {
                        nativeKeys ||= await global.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
                        const publicKey = new Uint8Array(await global.crypto.subtle.exportKey('raw', nativeKeys.publicKey));
                        if (verify(hex(publicKey))) {
                            const encoded = new Uint8Array(await global.crypto.subtle.exportKey('pkcs8', nativeKeys.privateKey));
                            // RFC 8410's minimal Ed25519 PrivateKeyInfo wraps a
                            // 32-byte seed. Reject unexpected encodings.
                            if (encoded.length !== 48 || hex(encoded.subarray(0, 16)) !== '302e020100300506032b657004220420') {
                                encoded.fill(0); throw Error('Unexpected Ed25519 private key encoding');
                            }
                            const seed = encoded.slice(16); encoded.fill(0);
                            global.postMessage({type:'NODE_IDENTITY', seed}, [seed.buffer]); return;
                        }
                        nativeKeys = null;
                    } else {
                        const seed = global.nacl.randomBytes(32), signing = global.nacl.sign.keyPair.fromSeed(seed);
                        const valid = verify(hex(signing.publicKey));
                        signing.secretKey.fill(0);
                        if (valid) { global.postMessage({type:'NODE_IDENTITY', seed}, [seed.buffer]); return; }
                        seed.fill(0);
                    }
                }
                global.postMessage({type:'EXPIRED'});
            } catch (_) { global.postMessage({type:'ERROR'}); }
            finally { mining = false; }
        };
    }
    global.DmashNodeIdentity = Object.freeze({verify, hash, mine, unlockDeviceIdentity, PREFIX});
    if (typeof module !== 'undefined') module.exports = global.DmashNodeIdentity;
})(typeof window !== 'undefined' ? window : globalThis);

'use strict';
// Encrypted, bounded durable relationships. Socket admission is never cached here.
(function(global) {
    const text = value => new TextEncoder().encode(value);
    const hex = bytes => Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    const field = (value,length) => {
        if(typeof value !== 'string' || !(new RegExp('^[0-9a-f]{'+length+'}$')).test(value)) throw Error('Invalid relationship field');
        return value;
    };
    class NodeRelationships {
        static async openForDevice(deviceRoot, localId, options={}) {
            const session=deviceRoot?.state;
            if(!session?.root) throw Error('Device must be unlocked');
            let key;
            try {
                key=await deviceRoot.derive(session.root,'dmash/node-storage',4,'directional-relationships');
                if(deviceRoot.state!==session) throw Error('Device session changed');
                return await this.open(key,localId,{...options,isCurrent:()=>deviceRoot.state===session && (options.isCurrent?.()??true)});
            } finally {key?.fill(0);}
        }
        static async open(storageKey, localId, {databaseName='dmash_node_relationships_v4', maxRelationships=4096, isCurrent=()=>true}={}) {
            field(localId,64);
            if(!(storageKey instanceof Uint8Array) || storageKey.length!==32 || !Number.isInteger(maxRelationships) || maxRelationships<1 || maxRelationships>65536) throw Error('Invalid Node storage parameters');
            const store = new NodeRelationships();
            store.localId=localId; store.maxRelationships=maxRelationships; store.isCurrent=isCurrent;
            store.transactions=new Set(); store.closed=false;
            try {
                const base = await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
                const derive = label => crypto.subtle.sign('HMAC',base,text(label));
                const alias = new Uint8Array(await derive('D-MASH|NODE-RELATIONSHIP-ALIAS|V4'));
                const encryption = new Uint8Array(await derive('D-MASH|NODE-RELATIONSHIP-STORAGE|V4'));
                try {
                    store.aliasKey=await crypto.subtle.importKey('raw',alias,{name:'HMAC',hash:'SHA-256'},false,['sign']);
                    store.encryptionKey=await crypto.subtle.importKey('raw',encryption,'AES-GCM',false,['encrypt','decrypt']);
                } finally {alias.fill(0);encryption.fill(0);}
                store.check();
                store.db=await new Promise((resolve,reject)=>{
                    const request=global.indexedDB.open(databaseName,1);
                    request.onupgradeneeded=()=>request.result.createObjectStore('relationships',{keyPath:'key'});
                    request.onsuccess=()=>{if(store.closed){request.result.close();reject(Error("Node storage session changed"));}else resolve(request.result);};
                    request.onerror=()=>reject(Error('Node relationship storage unavailable'));
                    request.onblocked=()=>reject(Error('Node relationship storage blocked'));
                });
                store.db.onversionchange=()=>store.close();
                const binding={version:4,localId};
                for(let attempt=0;attempt<8;attempt++) {
                    const row=await store.read('binding');
                    if(row) {
                        const value=await store.decrypt(row);
                        if(JSON.stringify(value)!==JSON.stringify(binding)) throw Error('Node relationship store identity changed');
                        return store;
                    }
                    // Metadata creation is refused if any orphan relationships exist.
                    if(await store.cas('binding',null,await store.encrypt('binding',binding),true)) return store;
                }
                throw Error('Node relationship storage contention');
            } catch(error) {store.close();throw error;}
        }
        check() {if(this.closed || !this.isCurrent()) throw Error('Node storage session changed');}
        transaction(mode,body) {
            this.check();
            return new Promise((resolve,reject)=>{
                const tx=this.db.transaction('relationships',mode);
                this.transactions.add(tx);
                let result;
                tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(result);}catch(error){reject(error);}};
                tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(Error('Node relationship transaction failed'));};
                try {body(tx.objectStore('relationships'),value=>{result=value;},tx);}
                catch(error) {tx.abort();reject(error);}
            });
        }
        read(key) {return this.transaction('readonly',(objectStore,done)=>{objectStore.get(key).onsuccess=event=>done(event.target.result||null);});}
        cas(key,revision,row,binding=false) {
            return this.transaction('readwrite',(objectStore,done,tx)=>{
                objectStore.get(key).onsuccess=event=>{
                    const current=event.target.result;
                    if((current?.revision??null)!==revision) {done(false);return;}
                    const write=()=>{try{this.check();objectStore.put({...row,key,revision:(revision??0)+1});done(true);}catch(_){tx.abort();}};
                    if(current) {write();return;}
                    objectStore.count().onsuccess=event=>{
                        if((binding && event.target.result!==0) || (!binding && event.target.result>=this.maxRelationships+1)) {tx.abort();return;}
                        write();
                    };
                };
            });
        }
        async encrypt(key,value) {
            this.check();
            const iv=crypto.getRandomValues(new Uint8Array(12));
            const bytes=text(JSON.stringify(value));
            try {
                const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text('D-MASH|NODE-RELATIONSHIP|V4|'+key)},this.encryptionKey,bytes);
                this.check();return {iv,ciphertext};
            } finally {bytes.fill(0);}
        }
        async decrypt(row) {
            this.check();
            let plaintext;
            try {
                plaintext=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:text('D-MASH|NODE-RELATIONSHIP|V4|'+row.key)},this.encryptionKey,row.ciphertext));
                this.check();return JSON.parse(new TextDecoder().decode(plaintext));
            } catch(_) {throw Error('Node relationship storage unreadable; recovery required');}
            finally {plaintext?.fill(0);}
        }
        async relationship(peerId,{inbound=null}={}) {
            this.check();field(peerId,64);
            if(peerId===this.localId) throw Error('Self relationship forbidden');
            if(inbound!==null) field(inbound,32);
            const pair=Uint8Array.from((this.localId+peerId).match(/../g),b=>parseInt(b,16));
            const key=hex(new Uint8Array(await crypto.subtle.sign('HMAC',this.aliasKey,pair)));
            this.check();
            for(let attempt=0;attempt<16;attempt++) {
                const row=await this.read(key);
                const value=row?await this.decrypt(row):{version:4,localId:this.localId,peerId,outbound:hex(crypto.getRandomValues(new Uint8Array(16))),inbound:null};
                if(Object.keys(value).sort().join(',')!=='inbound,localId,outbound,peerId,version' || value.version!==4 || value.localId!==this.localId || value.peerId!==peerId) throw Error('Invalid relationship binding');
                field(value.outbound,32);
                if(value.inbound!==null) {field(value.inbound,32);if(value.inbound===value.outbound) throw Error('Direction collision');}
                if(inbound!==null) {
                    if((value.inbound!==null && value.inbound!==inbound) || value.outbound===inbound) throw Error('Node relationship changed; explicit recovery required');
                    value.inbound=inbound;
                }
                if(await this.cas(key,row?.revision??null,await this.encrypt(key,value))) return {outbound:value.outbound,inbound:value.inbound};
            }
            throw Error('Node relationship storage contention');
        }
        close() {
            this.closed=true;
            for(const tx of this.transactions||[]) {try{tx.abort();}catch(_){}}
            this.transactions?.clear();
            this.db?.close();this.db=null;this.aliasKey=null;this.encryptionKey=null;
        }
    }
    global.DmashNodeRelationshipsV4=NodeRelationships;
    if(typeof module!=='undefined') module.exports=NodeRelationships;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
// Kpwd is password-equivalent, not PAKE. Never store it outside encrypted Node storage.
(function(global){
 const PROFILE='ARGON2ID_64M_T3_P1_V1',scriptUrl=global.document?.currentScript?.src||global.DMASH_NODE_WORKER_URLS?.admission;
 const text=value=>new TextEncoder().encode(value),hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const field=(value,length)=>{if(typeof value!=='string'||!(new RegExp('^[0-9a-f]{'+length+'}$')).test(value))throw Error('Invalid admission field');};
 function challengeBytes(challenge,issuer,applicant,transcriptHash){
  if(!challenge||Object.keys(challenge).sort().join(',')!=='epoch,expires_at,nonce,profile,salt,type,version'||challenge.type!=='NODE_PASSWORD_CHALLENGE'||challenge.version!==4||challenge.profile!==PROFILE)throw Error('Unsupported Node password profile');
  const salt=Uint8Array.from(atob(challenge.salt),c=>c.charCodeAt(0));
  if(salt.length!==16||btoa(String.fromCharCode(...salt))!==challenge.salt)throw Error('Invalid Node salt');
  field(challenge.epoch,32);field(challenge.nonce,64);field(issuer,64);field(applicant,64);
  if(issuer===applicant||!(transcriptHash instanceof Uint8Array)||transcriptHash.length!==32||!Number.isSafeInteger(challenge.expires_at)||challenge.expires_at<0)throw Error('Invalid admission context');
  return text('D-MASH|NODE-ADMISSION|V4\0'+[issuer,applicant,hex(transcriptHash),PROFILE,challenge.salt,challenge.epoch,challenge.nonce,challenge.expires_at].join('|'));
 }
 async function passwordProof(key,challenge,session,{now=Math.floor(Date.now()/1000)}={}){
  if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId))throw Error('Authenticated Node work required');
  if(!Number.isSafeInteger(now)||!(now<challenge.expires_at&&challenge.expires_at<=now+90))throw Error('Node password challenge expired');
  if(!(key instanceof Uint8Array)||key.length!==32)throw Error('Invalid Node password key');
  const bytes=challengeBytes(challenge,session.peerId,session.localId,session.transcriptHash);
  const cryptoKey=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const proof=hex(new Uint8Array(await crypto.subtle.sign('HMAC',cryptoKey,bytes)));
  if(session.closed)throw Error('Node session closed');
  return {type:'NODE_PASSWORD_PROOF',version:4,proof};
 }
 let job=null;
 function derivePasswordKey(password,salt,{signal}={}){
  if(typeof password!=='string'||!password||text(password).length>1024||!(salt instanceof Uint8Array)||salt.length!==16)return Promise.reject(Error('Invalid Node password parameters'));
  if(signal?.aborted)return Promise.reject(Error('Node password derivation cancelled'));
  if(job)return Promise.reject(Error('Node password worker busy'));
  if(!global.Worker||!scriptUrl)return Promise.reject(Error('Node password Worker required'));
  return new Promise((resolve,reject)=>{
   const worker=new Worker(scriptUrl);job=worker;
   const finish=(error,key)=>{
    if(job!==worker){key?.fill(0);return;}
    clearTimeout(timer);signal?.removeEventListener('abort',cancel);worker.terminate();job=null;
    if(error){key?.fill(0);reject(error);}else resolve(key);
   };
   const cancel=()=>finish(Error('Node password derivation cancelled'));
   const timer=setTimeout(()=>finish(Error('Node password derivation expired')),90000);
   signal?.addEventListener('abort',cancel,{once:true});
   worker.onerror=()=>finish(Error('Node password Worker failed'));
   worker.onmessage=({data})=>{
    if(!(data?.key instanceof Uint8Array)||data.key.length!==32)finish(Error('Node password derivation failed'));
    else finish(null,data.key);
   };
   worker.postMessage({password,salt});
  });
 }
 function context(session){
  if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||session.localId===session.peerId||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId))throw Error('Authenticated Node work required');
 }
 async function passwordCredential(password,options={}){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  return {profile:PROFILE,salt:btoa(String.fromCharCode(...salt)),epoch:hex(crypto.getRandomValues(new Uint8Array(16))),key:await derivePasswordKey(password,salt,options)};
 }
 class PasswordGate{
  constructor(credential,{clock=()=>Date.now()/1000}={}){
   if(credential?.profile!==PROFILE||!(credential.key instanceof Uint8Array)||credential.key.length!==32)throw Error('Invalid Node password credential');
   this.credential={...credential,key:credential.key.slice()};this.clock=clock;
   this.pending=new Map();this.attempted=new Map();this.authorized=new Set();this.failures=new Map();
   this.overloadUntil=0;this.generation=0;this.closed=false;
  }
  challenge(session){
   context(session);if(this.closed)throw Error('Node gate closed');
   const now=Math.floor(this.clock());
   for(const [peer,row] of this.failures)if(row.expires<=now)this.failures.delete(peer);
   const failure=this.failures.get(session.peerId);
   if(now<this.overloadUntil||(failure&&failure.until>now))throw Error('Node admission cooldown');
   if(!failure&&this.failures.size>=4096)throw Error('Node admission failure quota');
   if(this.attempted.has(session)||this.attempted.size>=256)throw Error('Node admission attempt limit');
   const challenge={type:'NODE_PASSWORD_CHALLENGE',version:4,profile:PROFILE,salt:this.credential.salt,epoch:this.credential.epoch,nonce:hex(crypto.getRandomValues(new Uint8Array(32))),expires_at:now+90};
   challengeBytes(challenge,session.localId,session.peerId,session.transcriptHash);
   const token={challenge,generation:this.generation};
   this.pending.set(session,token);this.attempted.set(session,token);return {...challenge};
  }
  async verify(session,response){
   context(session);if(this.closed)throw Error('Node gate closed');
   const token=this.pending.get(session);this.pending.delete(session);
   if(!token)return false;
   const failed=()=>{
    const now=Math.floor(this.clock());
    if(!this.failures.has(session.peerId)&&this.failures.size>=4096){this.overloadUntil=now+60;return false;}
    const count=Math.min(7,(this.failures.get(session.peerId)?.count||0)+1);
    this.failures.set(session.peerId,{count,until:now+Math.min(60,2**(count-1)),expires:now+600});return false;
   };
   if(Math.floor(this.clock())>=token.challenge.expires_at)return failed();
   if(!response||Object.keys(response).sort().join(',')!=='proof,type,version'||response.type!=='NODE_PASSWORD_PROOF'||response.version!==4)return failed();
   try{
    field(response.proof,64);
    const signature=Uint8Array.from(response.proof.match(/../g),b=>parseInt(b,16));
    const key=await crypto.subtle.importKey('raw',this.credential.key,{name:'HMAC',hash:'SHA-256'},false,['verify']);
    const valid=await crypto.subtle.verify('HMAC',key,signature,challengeBytes(token.challenge,session.localId,session.peerId,session.transcriptHash));
    if(this.closed||session.closed||token.generation!==this.generation||this.attempted.get(session)!==token)return false;
    if(Math.floor(this.clock())>=token.challenge.expires_at||!valid)return failed();
    this.failures.delete(session.peerId);this.authorized.add(session);return true;
   }catch(_){return failed();}
  }
  require(session){context(session);if(this.closed||!this.authorized.has(session))throw Error('Node password admission required');}
  forget(session){this.pending.delete(session);this.attempted.delete(session);this.authorized.delete(session);}
  revokeAll(){this.generation++;this.pending.clear();this.attempted.clear();this.authorized.clear();}
  close(){this.revokeAll();this.closed=true;this.credential.key.fill(0);}
 }
 if(typeof WorkerGlobalScope!=='undefined'&&global instanceof WorkerGlobalScope){
  importScripts('vendor/argon2-bundled.min.js');
  let used=false;
  global.onmessage=async({data})=>{
   if(used)return;used=true;
   try{
    if(typeof data?.password!=='string'||!data.password||text(data.password).length>1024||!(data.salt instanceof Uint8Array)||data.salt.length!==16)throw Error();
    const result=await global.argon2.hash({pass:data.password,salt:data.salt,time:3,mem:65536,parallelism:1,hashLen:32,type:global.argon2.ArgonType?.Argon2id??2});
    const key=new Uint8Array(result.hash);result.hash.fill(0);
    global.postMessage({key},[key.buffer]);
   }catch(_){global.postMessage({error:true});}
  };
 }
 const api=Object.freeze({PROFILE,challengeBytes,passwordProof,derivePasswordKey,passwordCredential,PasswordGate});
 global.DmashNodeAdmissionV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
// Pure transcript/validation contract. No route or mailbox authority is granted.
(function(global) {
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
    const field = (value, length) => {
        if (typeof value !== 'string' || !(new RegExp('^[0-9a-f]{'+length+'}$')).test(value)) throw Error('Invalid registration field');
        return value;
    };
    const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
    function resource(issuer, recipient, dnss, transcriptHash) {
        field(issuer,64); field(recipient,64); field(dnss,32);
        if (issuer === recipient || !(transcriptHash instanceof Uint8Array) || transcriptHash.length !== 32) throw Error('Invalid registration context');
        return ['D-MASH','NODE-DNSS','V4',issuer,recipient,dnss,hex(transcriptHash)].join('|');
    }
    function verifyRegistration(session, request, difficulty, {now = Math.floor(Date.now()/1000), expectedDnss = null} = {}) {
        try {
            if (session.version !== 4 || session.closed || session.localRole !== 'NODE' || session.peerRole !== 'NODE' ||
                !Number.isInteger(difficulty) || difficulty < 20 || difficulty > 24 || !Number.isSafeInteger(now)) return false;
            if (!exact(request,'dnss,pow,type') || request.type !== 'NODE_REGISTER') return false;
            field(request.dnss,32);
            if (expectedDnss !== null && request.dnss !== field(expectedDnss,32)) return false;
            const work = resource(session.peerId,session.localId,request.dnss,session.transcriptHash);
            const p = request.pow;
            if (!exact(p,'difficulty,digest,expires_at,nonce,resource,type,v') || p.v !== 1 || p.type !== 'DNSS' || p.resource !== work ||
                p.difficulty !== difficulty || !Number.isSafeInteger(p.expires_at) || p.expires_at <= now || p.expires_at > now+180 ||
                !Number.isSafeInteger(p.nonce) || p.nonce < 0) return false;
            field(p.digest,64);
            const digest = global.DmashResourcePow.activationDigest(session.localId,'DNSS',session.peerId,work,p.nonce,p.expires_at);
            return hex(digest) === p.digest && global.DmashResourcePow.leadingZeroBits(digest) >= difficulty;
        } catch (_) { return false; }
    }
    global.DmashNodeRegistrationV4 = Object.freeze({resource,verifyRegistration});
    if (typeof module !== 'undefined') module.exports = global.DmashNodeRegistrationV4;
})(typeof window !== 'undefined' ? window : globalThis);

"use strict";

/*
 * Browser implementation of D-MASH activation PoW.
 *
 * The JSON wire schema remains v1 for compatibility with DMP-C. The digest
 * transcript is V2 and deliberately uses SHA-256 because it is available in
 * every supported PWA runtime without shipping a second hash implementation
 * only for proof-of-work. Backend resource_pow.py mirrors these bytes exactly.
 */
(function (global) {
    const workerUrl = global.document?.currentScript?.src;
    const workers = new Set();
    const VERSION = 1;
    const DOMAIN = new TextEncoder().encode("D-MASH|ACTIVATION-POW|V2\0");
    const TYPES = new Set(["DNSS", "ENTRY_GRANT", "PRIVATE_ROUTE"]);
    const K = new Uint32Array([
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    const H0 = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const enc = new TextEncoder();
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    // At most five uint32 terms: their sum is exact in a JS Number. Avoid
    // allocating a rest array/reducer for every SHA-256 compression round.
    const add = (a, b, c = 0, d = 0, e = 0) => (a + b + c + d + e) >>> 0;
    const asBytes = (value, name) => {
        if (value instanceof Uint8Array) return new Uint8Array(value);
        if (typeof value === "string" && value.length) return enc.encode(value);
        throw new TypeError(name + " must be non-empty text or Uint8Array");
    };
    const u16 = value => Uint8Array.of((value >>> 8) & 255, value & 255);
    const u32 = value => Uint8Array.of((value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
    const u64 = value => {
        const n = typeof value === "bigint" ? value : BigInt(value);
        if (n < 0n || n >= (1n << 64n)) throw new RangeError("uint64 out of range");
        const out = new Uint8Array(8);
        for (let index = 7, x = n; index >= 0; index--, x >>= 8n) out[index] = Number(x & 255n);
        return out;
    };
    const join = (...parts) => {
        const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
        let at = 0; for (const part of parts) { out.set(part, at); at += part.length; }
        return out;
    };
    const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

    function compress(h, w, padded, offset) {
        for (let i = 0; i < 16; i++) {
            const at = offset + i * 4;
            w[i] = ((padded[at] << 24) | (padded[at + 1] << 16) | (padded[at + 2] << 8) | padded[at + 3]) >>> 0;
        }
        for (let i = 16; i < 64; i++) {
            const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
            const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
            w[i] = add(w[i - 16], s0, w[i - 7], s1);
        }
        let [a,b,c,d,e,f,g,hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
            const ch = ((e & f) ^ (~e & g)) >>> 0;
            const t1 = add(hh, S1, ch, K[i], w[i]);
            const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
            const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
            const t2 = add(S0, maj);
            hh = g; g = f; f = e; e = add(d, t1); d = c; c = b; b = a; a = add(t1, t2);
        }
        h[0]=add(h[0],a); h[1]=add(h[1],b); h[2]=add(h[2],c); h[3]=add(h[3],d);
        h[4]=add(h[4],e); h[5]=add(h[5],f); h[6]=add(h[6],g); h[7]=add(h[7],hh);
    }

    function sha256(message) {
        const input = message instanceof Uint8Array ? message : new Uint8Array(message);
        const bitLength = BigInt(input.length) * 8n;
        const paddedLength = Math.ceil((input.length + 1 + 8) / 64) * 64;
        const padded = new Uint8Array(paddedLength);
        padded.set(input); padded[input.length] = 0x80;
        for (let index = 0; index < 8; index++) padded[paddedLength - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 255n);

        const h = new Uint32Array(H0);
        const w = new Uint32Array(64);
        for (let offset = 0; offset < padded.length; offset += 64) {
            compress(h, w, padded, offset);
        }
        const out = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            out[i*4] = h[i] >>> 24; out[i*4+1] = h[i] >>> 16; out[i*4+2] = h[i] >>> 8; out[i*4+3] = h[i];
        }
        return out;
    }

    // Only the nonce changes during a mining job. Cache the SHA-256 state after
    // complete prefix blocks, and reuse buffers for the final one/two blocks.
    // This preserves every transcript byte and the exact required work target.
    function nonceHasher(prefix) {
        const blocks = Math.floor(prefix.length / 64) * 64;
        const initial = new Uint32Array(H0), w = new Uint32Array(64);
        for (let at = 0; at < blocks; at += 64) compress(initial, w, prefix, at);
        const remainder = prefix.length - blocks;
        const tail = new Uint8Array(Math.ceil((remainder + 8 + 1 + 8) / 64) * 64);
        tail.set(prefix.subarray(blocks)); tail[remainder + 8] = 0x80;
        const bits = BigInt(prefix.length + 8) * 8n;
        for (let i = 0; i < 8; i++) tail[tail.length - 1 - i] = Number((bits >> BigInt(i * 8)) & 255n);
        const view = new DataView(tail.buffer), h = new Uint32Array(8), digest = new Uint8Array(32);
        return nonce => {
            view.setUint32(remainder, Math.floor(nonce / 0x100000000), false);
            view.setUint32(remainder + 4, nonce >>> 0, false);
            h.set(initial);
            for (let at = 0; at < tail.length; at += 64) compress(h, w, tail, at);
            for (let i = 0; i < 8; i++) {
                digest[i*4] = h[i] >>> 24; digest[i*4+1] = h[i] >>> 16;
                digest[i*4+2] = h[i] >>> 8; digest[i*4+3] = h[i];
            }
            return digest;
        };
    }

    // Admission PoW appends an ASCII decimal counter, unlike activation's
    // eight-byte nonce. Reuse complete prefix blocks and the SHA work buffer
    // without changing a single transcript byte.
    function decimalSuffixHasher(prefix) {
        const input = asBytes(prefix, "prefix");
        const blocks = Math.floor(input.length / 64) * 64;
        const initial = new Uint32Array(H0), w = new Uint32Array(64);
        for (let at = 0; at < blocks; at += 64) compress(initial, w, input, at);
        const remainder = input.length - blocks;
        const tail = new Uint8Array(Math.ceil((remainder + 16 + 1 + 8) / 64) * 64);
        tail.set(input.subarray(blocks));
        const view = new DataView(tail.buffer), h = new Uint32Array(8), digest = new Uint8Array(32);
        return counter => {
            if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError("counter must be a non-negative safe integer");
            const decimal = String(counter), length = Math.ceil((remainder + decimal.length + 1 + 8) / 64) * 64;
            tail.fill(0, remainder);
            for (let i = 0; i < decimal.length; i++) tail[remainder + i] = decimal.charCodeAt(i);
            tail[remainder + decimal.length] = 0x80;
            const bits = (input.length + decimal.length) * 8;
            view.setUint32(length - 8, Math.floor(bits / 0x100000000), false);
            view.setUint32(length - 4, bits >>> 0, false);
            h.set(initial);
            for (let at = 0; at < length; at += 64) compress(h, w, tail, at);
            for (let i = 0; i < 8; i++) {
                digest[i*4] = h[i] >>> 24; digest[i*4+1] = h[i] >>> 16;
                digest[i*4+2] = h[i] >>> 8; digest[i*4+3] = h[i];
            }
            return digest;
        };
    }

    function leadingZeroBits(digest) {
        let bits = 0;
        for (const byte of digest) {
            if (byte === 0) { bits += 8; continue; }
            for (let mask = 0x80; mask && (byte & mask) === 0; mask >>= 1) bits++;
            break;
        }
        return bits;
    }

    function activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt) {
        if (!TYPES.has(activationType)) throw new TypeError("invalid activation type");
        const node = asBytes(nodeId, "nodeId");
        const key = asBytes(deviceTransportKey, "deviceTransportKey");
        const item = asBytes(resource, "resource");
        if (node.length > 0xffff || key.length > 0xffff || item.length > 0xffffffff) throw new RangeError("activation input too large");
        return { prefix: join(DOMAIN, u16(node.length), node, enc.encode(activationType), Uint8Array.of(0), u16(key.length), key, u32(item.length), item, u64(expiresAt)), item };
    }

    function activationDigest(nodeId, activationType, deviceTransportKey, resource, nonce, expiresAt) {
        const { prefix } = activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt);
        return sha256(join(prefix, u64(nonce)));
    }

    async function mineActivationPow({ nodeId, activationType, deviceTransportKey, resource, expiresAt, difficulty = 22, startNonce = 0, onProgress = null } = {}) {
        if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > 256) throw new RangeError("difficulty must be 0..256");
        if (!Number.isSafeInteger(startNonce) || startNonce < 0) throw new RangeError("startNonce must be a non-negative safe integer");
        const { prefix, item } = activationPrefix(nodeId, activationType, deviceTransportKey, resource, expiresAt);
        const hashNonce = nonceHasher(prefix);
        const started = global.performance?.now?.() ?? Date.now();
        for (let nonce = startNonce; Number.isSafeInteger(nonce); nonce++) {
            const digest = hashNonce(nonce);
            if (leadingZeroBits(digest) >= difficulty) {
                return Object.freeze({
                    v: VERSION, type: activationType,
                    resource: resource instanceof Uint8Array ? hex(item) : String(resource),
                    nonce, expires_at: expiresAt, difficulty, digest: hex(digest),
                    elapsed_ms: Math.round((global.performance?.now?.() ?? Date.now()) - started)
                });
            }
            if ((nonce - startNonce + 1) % 4096 === 0) {
                onProgress?.({ attempts: nonce - startNonce + 1, elapsedMs: (global.performance?.now?.() ?? Date.now()) - started });
                // A Dedicated Worker is cancelled by terminate(). Yielding
                // through browser timers here can throttle PoW in background
                // tabs; only the main-thread fallback needs cooperative yields.
                if (typeof global.importScripts !== 'function') await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        throw new Error("PoW nonce space exhausted");
    }

    function mineOffThread(options = {}) {
        if (!workerUrl || typeof global.Worker !== 'function') return mineActivationPow(options);
        return new Promise((resolve, reject) => {
            const worker = new global.Worker(workerUrl);
            const job = {worker, reject}; workers.add(job);
            const finish = () => { workers.delete(job); worker.terminate(); };
            worker.onmessage = ({data}) => {
                if (data.progress) { options.onProgress?.(data.progress); return; }
                finish();
                if (data.error) reject(new Error(data.error)); else resolve(data.proof);
            };
            worker.onerror = event => { finish(); reject(new Error(event.message || 'PoW worker failed')); };
            const {onProgress, ...input} = options;
            try { worker.postMessage(input); } catch (error) { finish(); reject(error); }
        });
    }
    function cancelAll() {
        for (const job of workers) { job.worker.terminate(); job.reject(new Error('PoW cancelled')); }
        workers.clear();
    }
    if (!global.document && typeof global.importScripts === 'function') {
        global.onmessage = async ({data}) => {
            try { global.postMessage({proof: await mineActivationPow({...data,
                onProgress: progress => global.postMessage({progress})})}); }
            catch (error) { global.postMessage({error: error.message}); }
        };
    }
    const api = Object.freeze({ VERSION, sha256, decimalSuffixHasher, leadingZeroBits, activationDigest, mineActivationPow: mineOffThread, cancelAll });
    global.DmashResourcePow = api;
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);

'use strict';
// One outgoing browser socket is a bidirectional NODE peer, never a DEVICE.
(function(global){
 const MAX_FRAME=2*1024*1024,MAX_QUEUE=4*1024*1024;
 class NodeSocketV4 {
  static async connect(url,signing,expectedNodeId,{signal}={}){
   const endpoint=new URL(url);
   if(endpoint.username||endpoint.password||endpoint.hash)throw Error('Invalid Node socket URL');
   if(endpoint.protocol!=='wss:'&&!(endpoint.protocol==='ws:'&&['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname)))throw Error('Node peering requires WSS');
   if(!global.DmashNodeIdentity.verify(expectedNodeId))throw Error('Node identity work required');
   const localId=Array.from(signing.publicKey,b=>b.toString(16).padStart(2,'0')).join('');
   if(!global.DmashNodeIdentity.verify(localId)||localId===expectedNodeId)throw Error('Independent Node identity required');
   if(signal?.aborted)throw Error('Node connection cancelled');
   const connection=new NodeSocketV4();
   connection.queue=[];connection.queueBytes=0;connection.closed=false;connection.reader=null;
   connection.abortController=new AbortController();connection.signal=connection.abortController.signal;
   const handshake=new global.DmashSecureSession.Initiator(signing,'NODE',4);
   try{connection.socket=new WebSocket(url);}catch(error){handshake.close();throw error;}
   const cancel=()=>connection.close();
   signal?.addEventListener('abort',cancel,{once:true});
   connection.cleanup=()=>signal?.removeEventListener('abort',cancel);
   connection.socket.onmessage=event=>connection.incoming(event.data);
   connection.socket.onclose=()=>connection.close();
   connection.socket.onerror=()=>connection.close();
   const deadline=setTimeout(()=>connection.close(),15000);
   try{
    await new Promise((resolve,reject)=>{
     connection.openReject=reject;
     connection.socket.onopen=()=>{connection.openReject=null;resolve();};
     if(connection.closed)reject(Error('Node connection closed'));
    });
    connection.sendRaw(handshake.initiate());
    const response=await connection.readRaw();
    const {auth,session}=await handshake.finish(response,expectedNodeId);
    try{connection.check();}catch(error){session.close();throw error;}
    connection.session=session;
    connection.sendRaw(auth);
    return connection;
   }catch(error){connection.close();throw error;}
   finally{clearTimeout(deadline);handshake.close();}
  }
  check(){if(this.closed||this.socket.readyState!==WebSocket.OPEN)throw Error('Node socket closed');}
  incoming(raw){
   if(this.closed)return;
   // Protocol output is canonical ASCII JSON, so character length bounds bytes.
   if(typeof raw!=='string'||raw.length>(this.session?MAX_FRAME:4096)||/[^\x00-\x7f]/.test(raw)){this.close();return;}
   if(this.reader){const reader=this.reader;this.reader=null;reader.resolve(raw);return;}
   if(this.queue.length>=64||this.queueBytes+raw.length>MAX_QUEUE){this.close();return;}
   this.queue.push(raw);this.queueBytes+=raw.length;
  }
  sendRaw(value){
   this.check();
   const raw=JSON.stringify(value);
   if(raw.length>MAX_FRAME||this.socket.bufferedAmount+raw.length>MAX_QUEUE)throw Error('Node send backpressure');
   this.socket.send(raw);
  }
  async readRaw(){
   this.check();
   if(this.reader)throw Error('Concurrent Node socket reader');
   let raw;
   if(this.queue.length){raw=this.queue.shift();this.queueBytes-=raw.length;}
   else raw=await new Promise((resolve,reject)=>{this.reader={resolve,reject};});
   try{return JSON.parse(raw);}catch(error){this.close();throw error;}
  }
  async sendJson(value){
   try{this.sendRaw(this.session.seal(value));}
   catch(error){this.close();throw error;}
  }
  async receiveJson(){
   try{return this.session.open(await this.readRaw());}
   catch(error){this.close();throw error;}
  }
  close(){
   if(this.closed)return;
   this.closed=true;this.abortController?.abort();this.cleanup?.();this.session?.close();
   this.openReject?.(Error('Node socket closed'));this.openReject=null;
   this.reader?.reject(Error('Node socket closed'));this.reader=null;
   this.queue=[];this.queueBytes=0;
   try{this.socket?.close(1000,'Node session ended');}catch(_){}
  }
 }
 global.DmashNodeSocketV4=NodeSocketV4;
 if(typeof module!=='undefined')module.exports=NodeSocketV4;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const workerUrl=global.document?.currentScript?.src||global.DMASH_NODE_WORKER_URLS?.channel,workers=new Set();
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const policy=value=>{
  if(!exact(value,'difficulty,password_challenge,type,version')||value.type!=='NODE_POLICY'||value.version!==4||!Number.isInteger(value.difficulty)||value.difficulty<20||value.difficulty>24||!(value.password_challenge===null||typeof value.password_challenge==='object'))throw Error('Invalid Node policy');
  return value;
 };
 function mine(options,signal){
  if(signal.aborted)return Promise.reject(Error('Node work cancelled'));
  if(!workerUrl||!global.Worker)return Promise.reject(Error('Node work Worker required'));
  if(workers.size>=2)return Promise.reject(Error('Node work admission limit'));
  return new Promise((resolve,reject)=>{
   const worker=new Worker(workerUrl);workers.add(worker);
   const finish=(error,proof)=>{
    if(!workers.has(worker))return;
    workers.delete(worker);clearTimeout(timer);signal.removeEventListener('abort',cancel);worker.terminate();
    if(error)reject(error);else resolve(proof);
   };
   const cancel=()=>finish(Error('Node work cancelled'));
   const timer=setTimeout(()=>finish(Error('Node work expired')),180000);
   signal.addEventListener('abort',cancel,{once:true});
   worker.onerror=()=>finish(Error('Node work Worker failed'));
   worker.onmessage=({data})=>data?.proof?finish(null,data.proof):finish(Error('Node work failed'));
   worker.postMessage(options);
  });
 }
 class NodeChannelV4{
  static async authorize(secure,relationships,{passwordGate=null,peerPasswordKey=null,requirePeerPassword=false,difficulty=22,signal}={}){
   const session=secure.session,abort=new AbortController(),cancel=()=>{abort.abort();secure.close();};
   signal?.addEventListener('abort',cancel,{once:true});
   secure.signal?.addEventListener('abort',cancel,{once:true});
   const timer=setTimeout(cancel,300000);
   try{
    if(signal?.aborted)throw Error('Node authorization cancelled');
    if(session.version!==4||session.closed||session.localRole!=='NODE'||session.peerRole!=='NODE'||!global.DmashNodeIdentity.verify(session.localId)||!global.DmashNodeIdentity.verify(session.peerId)||session.localId===session.peerId)throw Error('Authenticated Node work required');
    await secure.sendJson(policy({type:'NODE_POLICY',version:4,difficulty,password_challenge:passwordGate?await passwordGate.challenge(session):null}));
    const remote=policy(await secure.receiveJson()),challenge=remote.password_challenge;
    if(requirePeerPassword&&challenge===null)throw Error('Node password policy downgrade');
    let proof=null;
    if(challenge!==null){
     await global.DmashNodeAdmissionV4.passwordProof(new Uint8Array(32),challenge,session);
     if(!peerPasswordKey)throw Error('Node password credential missing');
     proof=await global.DmashNodeAdmissionV4.passwordProof(await peerPasswordKey(session.peerId,challenge),challenge,session);
    }
    await secure.sendJson({type:'NODE_ADMISSION',version:4,proof});
    const admission=await secure.receiveJson();
    if(!exact(admission,'proof,type,version')||admission.type!=='NODE_ADMISSION'||admission.version!==4)throw Error('Invalid Node admission');
    if(passwordGate){if(!await passwordGate.verify(session,admission.proof))throw Error('Node admission rejected');}
    else if(admission.proof!==null)throw Error('Unexpected Node password proof');
    await secure.sendJson({type:'NODE_ADMITTED',version:4});
    const admitted=await secure.receiveJson();
    if(!exact(admitted,'type,version')||admitted.type!=='NODE_ADMITTED'||admitted.version!==4)throw Error('Node admission incomplete');
    let relationship=await relationships.relationship(session.peerId);
    const sendRegistration=async()=>{
     const proof=await mine({nodeId:session.peerId,activationType:'DNSS',deviceTransportKey:session.localId,
       resource:global.DmashNodeRegistrationV4.resource(session.localId,session.peerId,relationship.outbound,session.transcriptHash),
       expiresAt:Math.floor(Date.now()/1000)+180,difficulty:remote.difficulty},abort.signal);
     await secure.sendJson({type:'NODE_REGISTER',dnss:relationship.outbound,pow:proof});
    };
    const receiveRegistration=async()=>{
     const value=await secure.receiveJson();
     if(!global.DmashNodeRegistrationV4.verifyRegistration(session,value,difficulty,{expectedDnss:relationship.inbound}))throw Error('Node registration rejected');
     return value;
    };
    const [,request]=await Promise.all([sendRegistration(),receiveRegistration()]);
    if(!global.DmashNodeRegistrationV4.verifyRegistration(session,request,difficulty,{expectedDnss:relationship.inbound}))throw Error('Node registration rejected');
    if(passwordGate)await passwordGate.require(session);
    relationship=await relationships.relationship(session.peerId,{inbound:request.dnss});
    await secure.sendJson({type:'NODE_AUTHORIZED',version:4,dnss:request.dnss});
    const authorized=await secure.receiveJson();
    if(!exact(authorized,'dnss,type,version')||authorized.type!=='NODE_AUTHORIZED'||authorized.version!==4||authorized.dnss!==relationship.outbound)throw Error('Node authorization incomplete');
    const channel=new NodeChannelV4();channel.secure=secure;channel.relationship=relationship;channel.passwordGate=passwordGate;channel.closed=false;
    await channel.requireAuthorized();return channel;
   }catch(error){passwordGate?.forget(session);secure.close();throw error;}
   finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);secure.signal?.removeEventListener('abort',cancel);abort.abort();}
  }
  async requireAuthorized(){
   if(this.closed||this.secure.session.closed)throw Error('Node channel closed');
   if(this.passwordGate)await this.passwordGate.require(this.secure.session);
  }
  async sendOperation(value){await this.requireAuthorized();return this.secure.sendJson(value);}
  async receiveOperation(){await this.requireAuthorized();const value=await this.secure.receiveJson();await this.requireAuthorized();return value;}
  close(){this.closed=true;this.passwordGate?.forget(this.secure.session);this.secure.close();}
 }
 if(typeof WorkerGlobalScope!=='undefined'&&global instanceof WorkerGlobalScope){
  importScripts('resource_pow.js');let used=false;
  global.onmessage=async({data})=>{
   if(used)return;used=true;
   try{
    if(!Number.isInteger(data?.difficulty)||data.difficulty<20||data.difficulty>24||!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=Date.now()/1000||data.expiresAt>Math.floor(Date.now()/1000)+180)throw Error();
    const deadline=Date.now()+180000;
    const proof=await global.DmashResourcePow.mineActivationPow({...data,onProgress:()=>{if(Date.now()>=deadline)throw Error('Node work expired');}});
    const {elapsed_ms,...wire}=proof;
    global.postMessage({proof:wire});
   }catch(_){global.postMessage({error:true});}
  };
 }
 global.DmashNodeChannelV4=NodeChannelV4;
 if(typeof module!=='undefined')module.exports=NodeChannelV4;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const MAX_HOPS=15,DEFAULT_MIN_HOPS=4;
 const bytes32=(value,name)=>{if(!(value instanceof Uint8Array)||value.length!==32)throw Error('Invalid '+name);return value;};
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 async function derive(base,domain,value){
  bytes32(base,'BaseNCRH');bytes32(value,'NCRH input');
  const prefix=new TextEncoder().encode('D-MASH|NCRH|V4|'+domain+'\0');
  const message=new Uint8Array(prefix.length+32);message.set(prefix);message.set(value,prefix.length);
  const key=await crypto.subtle.importKey('raw',base,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC',key,message)));
 }
 function routeNcrh(base,routeId){return derive(base,'ROUTE',routeId);}
 function extendNcrh(base,incoming){
  if(typeof incoming!=='string'||!/^[0-9a-f]{64}$/.test(incoming))throw Error('Invalid NCRH');
  return derive(base,'HOP',Uint8Array.from(incoming.match(/../g),b=>parseInt(b,16)));
 }
 function sampleHopTtl(minimum=DEFAULT_MIN_HOPS,maximum=MAX_HOPS){
  if(!Number.isInteger(minimum)||!Number.isInteger(maximum)||minimum<1||minimum>=maximum||maximum>MAX_HOPS)throw Error('Invalid random hop range');
  const width=maximum-minimum+1,limit=Math.floor(0x100000000/width)*width;
  const sample=new Uint32Array(1);
  do{crypto.getRandomValues(sample);}while(sample[0]>=limit);
  return minimum+sample[0]%width;
 }
 function consumeHop(ttl){
  if(!Number.isInteger(ttl)||ttl<1||ttl>MAX_HOPS)throw Error('Invalid hop TTL');
  return ttl-1;
 }
 const api=Object.freeze({MAX_HOPS,DEFAULT_MIN_HOPS,routeNcrh,extendNcrh,sampleHopTtl,consumeHop});
 global.DmashProbePrimitivesV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const MAX_BLOB=16384,MAX_LIFETIME=30*86400;
 const text=value=>new TextEncoder().encode(value);
 const join=(...parts)=>{const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const part of parts){out.set(part,at);at+=part.length;}return out;};
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=(value,size=32)=>{if(typeof value!=='string'||!(new RegExp('^[0-9a-f]{'+size*2+'}$')).test(value))throw Error('Invalid discovery encoding');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const integer=value=>{if(!Number.isSafeInteger(value)||value<0)throw Error('Invalid discovery integer');const out=new Uint8Array(8);new DataView(out.buffer).setBigUint64(0,BigInt(value));return out;};
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 // Public encoding guards only; group/signature verification remains in the vendor.
 // Small-order y encodings: libsodium 1.0.18 ge25519_has_small_order:
 // https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1022
 // Adapted encoding constants, source SHA256:
 // 40291bba865beab9817381460cda1d977a106c11cf4c393f854e25979d84bfc7
 // Lines 1022–1075. This is not a prime-subgroup membership proof.
/*
 * ISC License
 *
 * Copyright (c) 2013-2019
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 const ED_SMALL=new Set(['00'.repeat(32),'01'+'00'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ec'+'ff'.repeat(30)+'7f','ed'+'ff'.repeat(30)+'7f','ee'+'ff'.repeat(30)+'7f']);
 const P=unhex('ed'+'ff'.repeat(30)+'7f'),L=unhex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
 function lessLE(a,b){for(let i=a.length-1;i>=0;i--){if(a[i]!==b[i])return a[i]<b[i];}return false;}
 function edPoint(value){const y=unhex(value);y[31]&=127;if(!lessLE(y,P))fail('NON_CANONICAL_POINT');if(ED_SMALL.has(hex(y)))fail('SMALL_ORDER_POINT');}
 function edSignature(value){const sig=unhex(value,64);edPoint(hex(sig.subarray(0,32)));if(!lessLE(sig.subarray(32),L))fail('NON_CANONICAL_SIGNATURE');}
 function xPoint(value){const u=unhex(value);if(!lessLE(u,P))fail('NON_CANONICAL_POINT');const scalar=new Uint8Array(32);scalar[0]=8;if(!global.nacl.scalarMult(scalar,u).some(Boolean))fail('LOW_ORDER_KEY');}
 function certificateTranscript(cert){
  if(!exact(cert,'discovery_box,discovery_sign,expires_at,generation,issued_at,recipient_box,route_id,signature,version')||cert.version!==4)throw Error('Invalid discovery certificate');
  const keys=['route_id','discovery_sign','discovery_box','recipient_box'].map(name=>unhex(cert[name]));
  const dates=['generation','issued_at','expires_at'].map(name=>integer(cert[name]));
  if(cert.generation<1||cert.expires_at<=cert.issued_at||cert.expires_at-cert.issued_at>MAX_LIFETIME)throw Error('Invalid discovery validity');
  return join(text('D-MASH|DISCOVERY-CERT|V4\0'),...keys,...dates);
 }
 function verifyCertificate(cert,now=Math.floor(Date.now()/1000)){
  const transcript=certificateTranscript(cert);
  if(cert.issued_at>now+60||cert.expires_at<=now)throw Error('Discovery certificate expired');
  edPoint(cert.route_id);edPoint(cert.discovery_sign);xPoint(cert.discovery_box);xPoint(cert.recipient_box);edSignature(cert.signature);
  if(!global.nacl.sign.detached.verify(transcript,unhex(cert.signature,64),unhex(cert.route_id)))throw Error('Invalid discovery certificate signature');
  return transcript;
 }
 function issueCertificate(routeSign,discoverySign,discoveryBox,recipientBox,{generation,issuedAt,expiresAt}){
  const cert={version:4,route_id:hex(routeSign.publicKey),discovery_sign:hex(discoverySign),discovery_box:hex(discoveryBox),recipient_box:hex(recipientBox),generation,issued_at:issuedAt,expires_at:expiresAt,signature:''};
  cert.signature=hex(global.nacl.sign.detached(certificateTranscript(cert),routeSign.secretKey));return cert;
 }
 const b64=value=>btoa(String.fromCharCode(...value));
 function seal(publicKey,value){
  const raw=text(JSON.stringify(value));if(raw.length>MAX_BLOB-72)throw Error('Discovery payload too large');
  const ephemeral=global.nacl.box.keyPair(),nonce=global.nacl.randomBytes(24);
  try{return b64(join(ephemeral.publicKey,nonce,global.nacl.box(raw,nonce,publicKey,ephemeral.secretKey)));}
  finally{ephemeral.secretKey.fill(0);}
 }
 function openBox(privateKey,value){
  if(typeof value!=='string'||value.length>Math.ceil(MAX_BLOB/3)*4)throw Error('Invalid discovery box');
  const raw=Uint8Array.from(atob(value),c=>c.charCodeAt(0));
  if(raw.length<72||raw.length>MAX_BLOB||b64(raw)!==value)throw Error('Invalid discovery box');
  const plain=global.nacl.box.open(raw.subarray(56),raw.subarray(32,56),raw.subarray(0,32),privateKey);
  if(!plain)throw Error('Discovery authentication failed');
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}finally{plain.fill(0);}
 }
 function checkQuery(query,cert,now){
  if(!exact(query,'challenge,expires_at,reply_key,route_id,type,version')||query.type!=='ROUTE_QUERY'||query.version!==4||query.route_id!==cert.route_id)throw Error('Invalid discovery context');
  unhex(query.challenge);unhex(query.reply_key);integer(query.expires_at);
  if(query.expires_at<=now||query.expires_at>Math.min(now+180,cert.expires_at))throw Error('Discovery query expired');
  return query;
 }
 async function replyTranscript(query,cert){
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',join(certificateTranscript(cert),unhex(cert.signature,64))));
  return join(text('D-MASH|DISCOVERY-REPLY|V4\0'),unhex(query.challenge),unhex(query.reply_key),integer(query.expires_at),digest);
 }
 function createQuery(cert,{now=Math.floor(Date.now()/1000)}={}){
  verifyCertificate(cert,now);cert=Object.freeze({...cert});
  const reply=global.nacl.box.keyPair();
  try{
   const query=Object.freeze({type:'ROUTE_QUERY',version:4,route_id:cert.route_id,challenge:hex(global.nacl.randomBytes(32)),reply_key:hex(reply.publicKey),expires_at:Math.min(now+180,cert.expires_at)});
   return {blob:seal(unhex(cert.discovery_box),query),state:{query,certificate:cert,replyPrivate:reply.secretKey}};
  }catch(error){reply.secretKey.fill(0);throw error;}
 }
 async function answerQuery(blob,cert,discoverySign,discoveryBox,options={}){
  const clock=options.clock||(()=>options.now??Math.floor(Date.now()/1000)),now=clock();
  verifyCertificate(cert,now);cert={...cert};
  if(hex(discoverySign.publicKey)!==cert.discovery_sign||hex(discoveryBox.publicKey)!==cert.discovery_box)throw Error('Discovery key mismatch');
  const query=checkQuery(openBox(discoveryBox.secretKey,blob),cert,now);
  const signature=hex(global.nacl.sign.detached(await replyTranscript(query,cert),discoverySign.secretKey));
  checkQuery(query,cert,clock());
  const reply=seal(unhex(query.reply_key),{type:'ROUTE_REPLY',version:4,challenge:query.challenge,expires_at:query.expires_at,certificate:cert,signature});
  return options.withContext?{reply,expiresAt:query.expires_at}:reply;
 }
 async function verifyReply(blob,state,options={}){
  const clock=options.clock||(()=>options.now??Math.floor(Date.now()/1000)),now=clock();
  const cert=state.certificate;verifyCertificate(cert,now);const query=checkQuery(state.query,cert,now);
  const response=openBox(state.replyPrivate,blob);
  if(!exact(response,'certificate,challenge,expires_at,signature,type,version')||response.type!=='ROUTE_REPLY'||response.version!==4||response.challenge!==query.challenge||response.expires_at!==query.expires_at)throw Error('Discovery reply context mismatch');
  verifyCertificate(response.certificate,now);
  if(Object.keys(cert).some(key=>cert[key]!==response.certificate[key]))throw Error('Discovery certificate mismatch');
  edSignature(response.signature);
  if(!global.nacl.sign.detached.verify(await replyTranscript(query,cert),unhex(response.signature,64),unhex(cert.discovery_sign)))throw Error('Invalid discovery reply signature');
  checkQuery(query,cert,clock());
  return true;
 }
 const api=Object.freeze({validateEd25519PublicEncoding:edPoint,validateEd25519SignatureEncoding:edSignature,validateX25519PublicKey:xPoint,certificateTranscript,verifyCertificate,issueCertificate,seal,openBox,createQuery,answerQuery,verifyReply});
 global.DmashRouteDiscoveryV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 function sealPayload(recipientPublic,payload){
  if(typeof payload!=='string')throw Error('Opaque Account payload must be a string');
  return global.DmashRouteDiscoveryV4.seal(recipientPublic,{type:'RECIPIENT_PAYLOAD',version:2,packet_id:hex(crypto.getRandomValues(new Uint8Array(32))),payload});
 }
 function openPayload(privateKeys,blob){
  if(privateKeys==null||(Array.isArray(privateKeys)&&privateKeys.length===0))return {status:'deferred'};
  if(!Array.isArray(privateKeys)||privateKeys.length>2||privateKeys.some(key=>!(key instanceof Uint8Array)||key.length!==32))throw Error('Invalid recipient key set');
  if(!global.nacl?.box?.open||!global.DmashRouteDiscoveryV4)throw Error('Recipient crypto unavailable');
  for(const key of privateKeys){
   let value;try{value=global.DmashRouteDiscoveryV4.openBox(key,blob);}catch(_){continue;}
   if(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')==='packet_id,payload,type,version'&&value.type==='RECIPIENT_PAYLOAD'&&value.version===2&&typeof value.packet_id==='string'&&/^[0-9a-f]{64}$/.test(value.packet_id)&&typeof value.payload==='string')return {status:'accepted',packet_id:value.packet_id,payload:value.payload};
  }
  return {status:'discard'};
 }
 function coverBox(size=1024){
  if(!Number.isInteger(size)||size<256||size>16384)throw Error('Invalid cover size');
  const ephemeral=global.nacl.box.keyPair();
  try{const bytes=crypto.getRandomValues(new Uint8Array(size));bytes.set(ephemeral.publicKey);return btoa(String.fromCharCode(...bytes));}
  finally{ephemeral.secretKey.fill(0);}
 }
 const api=Object.freeze({sealPayload,openPayload,coverBox});global.DmashRecipientPayloadV4=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const token=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const opaque=value=>{
  if(typeof value!=='string'||value.length<96||value.length>21848)throw Error('Invalid opaque box');
  const raw=atob(value);if(raw.length<72||raw.length>16384||btoa(raw)!==value)throw Error('Invalid opaque box');
 };
 const labelKey=(peer,label)=>JSON.stringify([peer,label]);
 const randomLabel=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
 class NodeRoutingV4{
  constructor(base,{clock=()=>Date.now()/1000,monotonic=()=>performance.now()/1000}={}){
   if(!(base instanceof Uint8Array)||base.length!==32)throw Error('Invalid BaseNCRH');
   this.base=base.slice();this.clock=clock;this.monotonic=monotonic;this.peers=new Map();this.owned=[];this.labels=new Map();this.seen=new Map();
   this.queues=new Map();this.timers=new Map();this.senders=new Map();this.tasks=new Set();this.pending=new Set();this.rates=new Map();this.probes=[];this.coverHistory=[];this.coverTimer=null;this.coverPolicy=null;
   this.serviceQueries=new Map();this.discoveryRates=new Map();this.closed=false;this.stats={forwarded:0,received:0,probes:0,batches:0};
  }
  prune(){
   const now=this.clock();this.probes=this.probes.filter(row=>row.packet.expires_at>now&&this.peers.has(row.peer));for(const table of [this.labels,this.seen])for(const [key,row] of table)if(row.expires<=now)table.delete(key);
  }
  label(peer,target,expires){
   this.prune();if(this.labels.size>=4096)throw Error('Node label quota');
   const label=randomLabel();this.labels.set(labelKey(peer,label),{peer,target,expires});return label;
  }
  async dedupe(kind,blob,expires){
   const hash=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(blob))));
   if(this.closed)throw Error('Node runtime closed');
   this.prune();const key=kind+hash;if(this.seen.has(key))return false;
   if(this.seen.size>=4096)throw Error('Node duplicate quota');this.seen.set(key,{expires});return true;
  }
  bindLocal(certificate,sign,box,handler){
   global.DmashRouteDiscoveryV4.verifyCertificate(certificate,Math.floor(this.clock()));
   if(this.closed||this.owned.length>=32)throw Error('Local route unavailable');
   if(hex(sign.publicKey)!==certificate.discovery_sign||hex(box.publicKey)!==certificate.discovery_box)throw Error('Discovery key mismatch');
   if(this.owned.some(row=>row.certificate.route_id===certificate.route_id))throw Error('Route already bound');
   const binding={certificate:{...certificate},sign,box,handler};this.owned.push(binding);
   const task=this.answerCached(binding);this.tasks.add(task);task.finally(()=>this.tasks.delete(task));return binding;
  }
  async answerCached(binding){
   this.prune();for(const row of [...this.probes])try{await this.answerBinding(row.peer,row.packet,binding);}catch(_){}
  }
  async answerBinding(peer,packet,binding){
   if(this.closed||!this.peers.has(peer)||packet.expires_at<=this.clock())return;
   let answer;try{answer=await global.DmashRouteDiscoveryV4.answerQuery(packet.box,binding.certificate,binding.sign,binding.box,{clock:()=>Math.floor(this.clock()),withContext:true});}catch(_){return;}
   if(this.closed||!this.peers.has(peer)||packet.expires_at<=this.clock())return;
   const expires=Math.min(packet.expires_at,answer.expiresAt),offer=this.label(peer,binding.handler,expires);
   this.enqueue(peer,{type:'DATA',version:4,label:packet.return_label,offer,payload:answer.reply,expires_at:expires});
  }
  async addPeer(peer,channel){
   if(this.closed||this.peers.has(peer)||this.peers.size>=8)throw Error('Node peer unavailable');
   await channel.requireAuthorized();
   if(this.closed||this.peers.has(peer)||this.peers.size>=8)throw Error('Node peer unavailable');
   this.peers.set(peer,channel);const task=this.read(peer,channel);this.tasks.add(task);task.finally(()=>this.tasks.delete(task));
  }
  async read(peer,channel){
   try{
    while(!this.closed){
     const batch=await channel.receiveOperation();
     if(!exact(batch,'packets,type,version')||batch.type!=='MESH_BATCH'||batch.version!==4||!Array.isArray(batch.packets)||batch.packets.length<1||batch.packets.length>32||JSON.stringify(batch).length>256*1024)throw Error('Invalid Node batch');
     for(const packet of batch.packets){await channel.requireAuthorized();await this.receive(peer,packet);}
    }
   }catch(_){}
   finally{if(this.peers.get(peer)===channel)this.removePeer(peer);channel.close();}
  }
  removePeer(peer){
   for(const [key,q]of this.serviceQueries)if(q.peer===peer){clearTimeout(q.timer);q.reject(Error('SERVICE_CHANNEL_CLOSED'));this.serviceQueries.delete(key);}
   this.peers.delete(peer);this.queues.delete(peer);clearTimeout(this.timers.get(peer));this.timers.delete(peer);this.rates.delete(peer);this.discoveryRates.delete(peer);
   for(const [key,row] of this.labels)if(row.peer===peer||(Array.isArray(row.target)&&row.target[0]===peer))this.labels.delete(key);
   if(!this.peers.size)for(const pending of this.pending)pending.reject(Error('Node path unavailable'));
  }
  enqueue(peer,packet){
   if(this.closed||!this.peers.has(peer))throw Error('Node path unavailable');
   const queue=this.queues.get(peer)||[];this.queues.set(peer,queue);
   const size=JSON.stringify(packet).length;
   let total=0;for(const q of this.queues.values())for(const row of q)total+=row.size;
   if(size>32768||queue.length>=128||total+size>1024*1024)throw Error('Node forwarding queue full');
   queue.push({packet,size,deadline:this.monotonic()+0.5});
   if(!this.timers.has(peer)&&!this.senders.has(peer))this.arm(peer);
  }
  arm(peer){
   const queue=this.queues.get(peer);if(!queue?.length||this.closed)return;
   this.timers.set(peer,setTimeout(()=>this.startSend(peer),Math.max(0,queue[0].deadline-this.monotonic())*1000));
  }
  startSend(peer){this.timers.delete(peer);const task=Promise.resolve().then(()=>this.flush(peer));this.senders.set(peer,task);}
  async flush(peer){
   let timer;
   try{
    const queue=this.queues.get(peer)||[],deadline=queue[0]?.deadline||0,batch=[];let size=0;
    while(queue.length&&queue[0].deadline<deadline+0.5&&batch.length<32){
     const row=queue[0];if(size+row.size>240*1024)break;queue.shift();
     if(row.packet.expires_at>this.clock()){batch.push(row.packet);size+=row.size;}
    }
    if(batch.length){
     await Promise.race([this.peers.get(peer).sendOperation({type:'MESH_BATCH',version:4,packets:batch}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Node send timeout')),10000);})]);
     this.stats.batches++;
    }
   }catch(_){const channel=this.peers.get(peer);this.removePeer(peer);channel?.close();}
   finally{clearTimeout(timer);this.senders.delete(peer);this.arm(peer);}
  }
  async discover(certificate,{signal}={}){
   if(this.closed||!this.peers.size||signal?.aborted)throw Error('Node path unavailable');
   if(this.pending.size>=8)throw Error('Node discovery quota');
   const pinned={...certificate};global.DmashRouteDiscoveryV4.verifyCertificate(pinned,Math.floor(this.clock()));
   let resolve,reject,done=false,current=null;const timers=new Set();
   const result=new Promise((yes,no)=>{resolve=v=>{if(!done){done=true;yes(v);}};reject=e=>{if(!done){done=true;no(e);}};});result.catch(()=>{});
   const pending={reject};this.pending.add(pending);const cancel=()=>reject(Error('Node discovery cancelled'));signal?.addEventListener('abort',cancel,{once:true});
   const retire=()=>{if(!current)return;current.state.replyPrivate.fill(0);for(const [key,row]of this.labels)if(row.target===current.accept)this.labels.delete(key);current=null;};
   const attempt=async()=>{
    if(done||this.closed||signal?.aborted)return;
    retire();const {blob,state}=global.DmashRouteDiscoveryV4.createQuery(pinned,{now:Math.floor(this.clock())}),expires=state.query.expires_at;
    const entry={state,accept:null};entry.accept=async(peer,packet)=>{if(done||current!==entry)return;let valid;try{valid=await global.DmashRouteDiscoveryV4.verifyReply(packet.payload,state,{clock:()=>Math.floor(this.clock())});}catch(_){return;}if(valid&&!done&&current===entry&&!this.closed&&expires>this.clock()&&this.peers.has(peer))resolve({peer,label:packet.offer,expires_at:Math.min(expires,packet.expires_at),channel:this.peers.get(peer)});};current=entry;
    await this.dedupe('PROBE',blob,expires);const ncrh=await global.DmashProbePrimitivesV4.routeNcrh(this.base,Uint8Array.from(pinned.route_id.match(/../g),v=>parseInt(v,16)));if(done||current!==entry||this.closed)return;
    const ttl=global.DmashProbePrimitivesV4.sampleHopTtl(),bucket=Math.floor(this.clock()/60);let sent=0;
    for(const peer of this.peers.keys()){const previous=this.discoveryRates.get(peer),count=previous?.bucket===bucket?previous.count:0;if(count>=24)continue;this.discoveryRates.set(peer,{bucket,count:count+1});const label=this.label(peer,entry.accept,expires);this.enqueue(peer,{type:'PROBE',version:4,box:blob,return_label:label,ncrh,ttl,expires_at:expires});sent++;}
    if(!sent)throw Error('Node discovery rate limit');
   };
   try{
    for(const delay of [5000,15000])timers.add(setTimeout(()=>{void attempt().catch(reject);},delay));
    timers.add(setTimeout(()=>reject(Error('Node discovery expired')),30000));
    await attempt();return await result;
   }finally{done=true;for(const timer of timers)clearTimeout(timer);signal?.removeEventListener('abort',cancel);this.pending.delete(pending);retire();}
  }
  send(route,payload,replyHandler){
   if(route.expires_at<=this.clock()||this.peers.get(route.peer)!==route.channel)throw Error('Node route expired or replaced');
   opaque(payload);const offer=this.label(route.peer,replyHandler,route.expires_at);
   this.enqueue(route.peer,{type:'DATA',version:4,label:route.label,offer,payload,expires_at:route.expires_at});
  }
  startCover({minimum=15,maximum=45}={}){
   if(this.closed||!Number.isInteger(minimum)||!Number.isInteger(maximum)||minimum<15||minimum>=maximum||maximum>300)throw Error('Invalid cover scheduling policy');
   this.stopCover();this.coverPolicy={minimum,maximum};this.scheduleCover();
  }
  stopCover(){this.coverPolicy=null;clearTimeout(this.coverTimer);this.coverTimer=null;}
  scheduleCover(){
   if(this.closed||!this.coverPolicy)return;
   const {minimum,maximum}=this.coverPolicy,width=(maximum-minimum)*1000+1,limit=Math.floor(0x100000000/width)*width,sample=new Uint32Array(1);
   do{crypto.getRandomValues(sample);}while(sample[0]>=limit);
   this.coverTimer=setTimeout(()=>{
    this.coverTimer=null;if(this.closed||!this.coverPolicy)return;
    try{this.injectCoverOnce();}catch(_){}finally{this.scheduleCover();}
   },minimum*1000+sample[0]%width);
  }
  injectCoverOnce(size=1024){
   if(this.closed||[...this.queues.values()].some(queue=>queue.length)||this.senders.size)return false;
   const now=this.monotonic();this.coverHistory=this.coverHistory.filter(row=>row.at>now-60);
   if(!Number.isInteger(size)||size<256||size>16384)throw Error('Invalid cover size');
   if(this.coverHistory.length>=4||this.coverHistory.reduce((sum,row)=>sum+row.size,0)+size>16384)return false;
   this.prune();const candidates=[];
   for(const row of this.labels.values())if(Array.isArray(row.target)&&this.peers.has(row.target[0])&&row.expires>this.clock()+2&&this.coverHistory.filter(entry=>entry.peer===row.target[0]).length<2)candidates.push(row);
   if(!candidates.length)return false;
   const limit=Math.floor(0x100000000/candidates.length)*candidates.length,sample=new Uint32Array(1);
   do{crypto.getRandomValues(sample);}while(sample[0]>=limit);
   const row=candidates[sample[0]%candidates.length],peer=row.target[0];
   this.send({peer,label:row.target[1],expires_at:row.expires,channel:this.peers.get(peer)},global.DmashRecipientPayloadV4.coverBox(size),async()=>{});
   this.coverHistory.push({at:now,peer,size});return true;
  }
  requestService(peer){
   const channel=this.peers.get(peer);if(this.closed||!channel||this.serviceQueries.size>=8)return Promise.reject(Error('SERVICE_UNAVAILABLE'));
   const challenge=randomLabel();return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.serviceQueries.delete(challenge);reject(Error('SERVICE_TIMEOUT'));},10000);this.serviceQueries.set(challenge,{peer,channel,resolve,reject,timer});try{this.enqueue(peer,{type:'SERVICE_QUERY',version:4,challenge,expires_at:Math.floor(this.clock())+10});}catch(e){clearTimeout(timer);this.serviceQueries.delete(challenge);reject(e);}});
  }
  async receive(peer,packet){
   if(!packet||packet.version!==4||!Number.isSafeInteger(packet.expires_at)||packet.expires_at>this.clock()+180)throw Error('Invalid Node packet');
   const expires=packet.expires_at;if(expires<=this.clock())return;
   if(packet.type==='SERVICE_UNAVAILABLE'){
    if(!exact(packet,'challenge,code,expires_at,type,version')||!token(packet.challenge)||packet.code!=='SERVICE_UNAVAILABLE')throw Error('SERVICE_REPLY_INVALID');
    const q=this.serviceQueries.get(packet.challenge);if(!q)return;if(q.peer!==peer||this.peers.get(peer)!==q.channel)throw Error('SERVICE_CONTEXT');
    this.serviceQueries.delete(packet.challenge);clearTimeout(q.timer);q.reject(Error('SERVICE_UNAVAILABLE'));return;
   }
   if(packet.type==='SERVICE_REPLY'){
    if(!exact(packet,'challenge,descriptor,expires_at,type,version')||!token(packet.challenge))throw Error('SERVICE_REPLY_INVALID');
    const q=this.serviceQueries.get(packet.challenge);if(!q)return;if(q.peer!==peer||this.peers.get(peer)!==q.channel)throw Error('SERVICE_CONTEXT');
    this.serviceQueries.delete(packet.challenge);clearTimeout(q.timer);q.resolve({descriptor:packet.descriptor,challenge:packet.challenge,channel:q.channel});return;
   }
   if(packet.type==='PROBE'){
    if(!exact(packet,'box,expires_at,ncrh,return_label,ttl,type,version')||!token(packet.return_label)||!token(packet.ncrh))throw Error('Invalid Probe');
    const remaining=global.DmashProbePrimitivesV4.consumeHop(packet.ttl),blob=packet.box;
    opaque(blob);
    const bucket=Math.floor(this.clock()/60),rate=this.rates.get(peer),count=rate?.bucket===bucket?rate.count:0;
    if(count>=32)throw Error('Probe rate limit');this.rates.set(peer,{bucket,count:count+1});
    if(!await this.dedupe('PROBE',blob,expires)||!this.peers.has(peer))return;this.stats.probes++;
    this.probes.push({peer,packet:{...packet}});this.probes=this.probes.slice(-64);
    if(remaining){
     const ncrh=await global.DmashProbePrimitivesV4.extendNcrh(this.base,packet.ncrh);
     if(this.closed||!this.peers.has(peer))return;
     for(const neighbor of this.peers.keys())if(neighbor!==peer){
      const label=this.label(neighbor,[peer,packet.return_label],expires);this.enqueue(neighbor,{...packet,return_label:label,ttl:remaining,ncrh});
     }
    }
    for(const binding of this.owned)await this.answerBinding(peer,packet,binding);
   }else if(packet.type==='DATA'){
    if(!exact(packet,'expires_at,label,offer,payload,type,version')||!token(packet.label)||!token(packet.offer))throw Error('Invalid DATA');
    opaque(packet.payload);this.prune();const binding=this.labels.get(labelKey(peer,packet.label));if(!binding||expires>binding.expires)return;
    // A fresh authenticated hop grant may retry the same recipient box.
    // Keep duplicate suppression within the validated peer/label namespace.
    if(!await this.dedupe('DATA:'+labelKey(peer,packet.label),packet.payload,expires)||this.labels.get(labelKey(peer,packet.label))!==binding||!this.peers.has(peer))return;this.stats.received++;
    const target=binding.target;
    if(Array.isArray(target)){
     const offer=this.label(target[0],[peer,packet.offer],expires);this.enqueue(target[0],{...packet,label:target[1],offer});this.stats.forwarded++;
    }else await target(peer,packet);
   }else throw Error('Unsupported Node packet');
  }
  async close(){
   this.closed=true;this.stopCover();
   for(const q of this.serviceQueries.values()){clearTimeout(q.timer);q.reject(Error('SERVICE_RUNTIME_CLOSED'));}this.serviceQueries.clear();
   for(const pending of this.pending)pending.reject(Error('Node runtime closed'));
   for(const timer of this.timers.values())clearTimeout(timer);
   for(const channel of this.peers.values())channel.close();
   await Promise.allSettled([...this.tasks,...this.senders.values()]);
   this.peers.clear();this.labels.clear();this.queues.clear();this.seen.clear();this.owned=[];this.rates.clear();this.probes=[];this.base.fill(0);
  }
 }
 global.DmashNodeRoutingV4=NodeRoutingV4;
 if(typeof module!=='undefined')module.exports=NodeRoutingV4;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const text=value=>new TextEncoder().encode(value);
 const token=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 const slot=value=>typeof value==='string'&&value.length>0&&value.length<=512;
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const bucket=key=>key==='owner'||key.startsWith('binding:')?'bindings':'records';
 const size=row=>{
  const bytes=row?.ciphertext?.byteLength;
  if(!Number.isSafeInteger(bytes)||bytes<16)return 65536+128;
  return bytes+128;
 };
 class InboxStore{
  constructor({databaseName='dmash_node_inbox_v4',maxRecords=4096,maxBytes=32*1024*1024,isCurrent=()=>true}={}){
   if(!Number.isInteger(maxRecords)||maxRecords<1||maxRecords>16384||!Number.isInteger(maxBytes)||maxBytes<1024||maxBytes>64*1024*1024)throw Error('Invalid Inbox quota');
   Object.assign(this,{databaseName,maxRecords,maxBytes,isCurrent,closed:false,transactions:new Set()});
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Node Inbox closed');}
  async open(){
   this.check();
   this.db=await new Promise((resolve,reject)=>{
    const request=global.indexedDB.open(this.databaseName,1);
    request.onupgradeneeded=()=>{request.result.createObjectStore('records',{keyPath:'key'});request.result.createObjectStore('usage',{keyPath:'key'});request.result.createObjectStore('bindings',{keyPath:'key'});};
    request.onerror=request.onblocked=()=>reject(Error('Node Inbox unavailable'));
    request.onsuccess=()=>{try{this.check();resolve(request.result);}catch(error){request.result.close();reject(error);}};
   });
   this.db.onversionchange=()=>this.close();
   return this;
  }
  async reconcile(){
   for(const kind of ['records','bindings'])await this.transaction('readwrite',(store,done,fail,usage)=>{store.getAll().onsuccess=e=>{
    try{const rows=e.target.result;usage.put({key:kind,count:rows.length,bytes:rows.reduce((n,row)=>n+size(row),0)});done(true);}catch(error){fail(error);}
   };},kind);
  }
  transaction(mode,body,kind='records'){
   this.check();return new Promise((resolve,reject)=>{
    const tx=this.db.transaction(['records','bindings','usage'],mode);this.transactions.add(tx);let result,error;
    tx.oncomplete=()=>{this.transactions.delete(tx);try{this.check();resolve(result);}catch(e){reject(e);}};
    tx.onabort=tx.onerror=()=>{this.transactions.delete(tx);reject(error||Error('Node Inbox transaction failed'));};
    try{body(tx.objectStore(kind),value=>{result=value;},failure=>{error=failure;tx.abort();},tx.objectStore('usage'));}catch(e){error=e;tx.abort();}
   });
  }
  read(key){return this.transaction('readonly',(store,done)=>{store.get(key).onsuccess=e=>done(e.target.result||null);},bucket(key));}
  all(){return this.transaction('readonly',(store,done)=>{store.getAll().onsuccess=e=>done(e.target.result);});}
  allBindings(){return this.transaction('readonly',(store,done)=>{store.getAll().onsuccess=e=>done(e.target.result);},'bindings');}
  cas(key,revision,row,{guard=()=>true}={}){
   const kind=bucket(key);
   return this.transaction('readwrite',(store,done,fail,usage)=>{
    store.get(key).onsuccess=e=>{
     const current=e.target.result;
     if((current?.revision??null)!==revision){done(false);return;}
     usage.get(kind).onsuccess=event=>{
      try{
       this.check();if(!guard())throw Error('Inbox owner session changed');const totals=event.target.result;
       if(!Number.isSafeInteger(totals?.count)||!Number.isSafeInteger(totals?.bytes))throw Error('Inbox quota metadata missing');
       if(key==='owner'&&!current&&totals.count!==0)throw Error('Inbox owner missing');
       const count=totals.count+(row===null?-1:current?0:1);
       const bytes=totals.bytes-(current?size(current):0)+(row===null?0:size(row));
       if(row===null&&!current){done(false);return;}
       if(row!==null&&((bytes>(kind==='bindings'?256*1024:this.maxBytes)&&bytes>totals.bytes)||(count>(kind==='bindings'?33:this.maxRecords)&&count>totals.count)))throw Error('Node Inbox quota reached');
       if(row===null)store.delete(key);else store.put({...row,key,revision:(revision??0)+1});
       usage.put({key:kind,count,bytes});done(true);
      }catch(error){fail(error);}
     };
    };
   },kind);
  }
  promote(sourceKey,sourceRevision,targetKey,targetRevision,row){
   if(!token(sourceKey)||!token(targetKey)||sourceKey===targetKey)throw Error('Invalid Inbox promotion');
   return this.transaction('readwrite',(store,done,fail,usage)=>{
    store.get(sourceKey).onsuccess=sourceEvent=>{
     const source=sourceEvent.target.result;
     if(!source||source.revision!==sourceRevision){done(false);return;}
     store.get(targetKey).onsuccess=targetEvent=>{
      const target=targetEvent.target.result;
      if((target?.revision??null)!==targetRevision){done(false);return;}
      usage.get('records').onsuccess=event=>{
       try{
        this.check();const totals=event.target.result;
        const next=row||target;if(!next)throw Error('Missing promotion target');
        const count=totals.count-(target?1:0),bytes=totals.bytes-size(source)-(target?size(target):0)+size(next);
        if((bytes>this.maxBytes&&bytes>totals.bytes)||(count>this.maxRecords&&count>totals.count))throw Error('Inbox quota reached');
        if(row)store.put({...row,key:targetKey,revision:(targetRevision??0)+1});
        store.delete(sourceKey);usage.put({key:'records',count,bytes});done(true);
       }catch(error){fail(error);}
      };
     };
    };
   });
  }
  close(){this.closed=true;for(const tx of this.transactions)try{tx.abort();}catch(_){}this.transactions.clear();this.db?.close();this.db=null;}
 }
 class NodeInboxV4{
  static async open(storageKey,localId,{store,isCurrent=()=>true,clock=()=>Date.now(),...options}={}){
   if(!(storageKey instanceof Uint8Array)||storageKey.length!==32||!token(localId))throw Error('Invalid Inbox material');
   const inbox=new NodeInboxV4();Object.assign(inbox,{localId,isCurrent,clock,closed:false});
   inbox.store=store||new InboxStore({...options,isCurrent:()=>!inbox.closed&&isCurrent()});
   try{
    const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
    for(const [name,algorithm,usages] of [['aliasKey',{name:'HMAC',hash:'SHA-256'},['sign']],['encryptionKey','AES-GCM',['encrypt','decrypt']]]){
     const material=new Uint8Array(await crypto.subtle.sign('HMAC',base,text('D-MASH|NODE-INBOX|V4|'+name)));
     try{inbox[name]=await crypto.subtle.importKey('raw',material,algorithm,false,usages);}finally{material.fill(0);}
    }
    inbox.check();await inbox.store.open();
    for(let attempt=0;attempt<8;attempt++){
     const row=await inbox.store.read('owner');
     if(row){const value=await inbox.decrypt(row);if(value.kind!=='owner'||value.version!==1||value.localId!==localId)throw Error('Node Inbox owner changed');await inbox.store.reconcile?.();return inbox;}
     if((await inbox.store.all()).length)throw Error('Node Inbox owner missing');
     await inbox.store.reconcile?.();
     if(await inbox.store.cas('owner',null,await inbox.encrypt('owner',{kind:'owner',version:1,localId})))return inbox;
    }
    throw Error('Node Inbox contention');
   }catch(error){inbox.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Node Inbox closed');}
  async alias(label){this.check();const result=hex(new Uint8Array(await crypto.subtle.sign('HMAC',this.aliasKey,text(label))));this.check();return result;}
  async encrypt(key,value){
   this.check();const iv=crypto.getRandomValues(new Uint8Array(12)),bytes=text(JSON.stringify(value));
   try{const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:text('D-MASH|NODE-INBOX|V4|'+this.localId+'|'+key)},this.encryptionKey,bytes);this.check();return {iv,ciphertext};}
   finally{bytes.fill(0);}
  }
  async decrypt(row){
   this.check();let bytes;
   if(!row||!(row.key==='owner'||token(row.key)||(typeof row.key==='string'&&row.key.startsWith('binding:')&&token(row.key.slice(8))))||row.iv?.byteLength!==12||!Number.isSafeInteger(row.ciphertext?.byteLength)||row.ciphertext.byteLength<16||row.ciphertext.byteLength>65536||!Number.isSafeInteger(row.revision)||row.revision<1)throw Error('Invalid Inbox row');
   try{bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:text('D-MASH|NODE-INBOX|V4|'+this.localId+'|'+row.key)},this.encryptionKey,row.ciphertext));this.check();return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
   finally{bytes?.fill(0);}
  }
  async receive(routeId,accountSlot,blob,privateKeys){
   this.check();if(!token(routeId)||!slot(accountSlot)||typeof blob!=='string'||blob.length<96||blob.length>21848)throw Error('Invalid local delivery');
   let raw;try{raw=atob(blob);}catch(_){throw Error('Invalid local delivery encoding');}
   if(raw.length<72||raw.length>16384||btoa(raw)!==blob)throw Error('Invalid local delivery encoding');
   const opened=global.DmashRecipientPayloadV4.openPayload(privateKeys,blob);
   if(opened.status==='discard')return {status:'discard'};
   const deferred=opened.status==='deferred';
   const id=deferred?hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(blob)))):opened.packet_id;
   const key=await this.alias((deferred?'deferred|':'packet|')+routeId+'|'+id);
   const value={kind:deferred?'deferred':'pending',routeId,accountSlot,receivedAt:this.clock(),
    ...(deferred?{blob}:{packetId:id,payload:opened.payload})};
   const inserted=await this.store.cas(key,null,await this.encrypt(key,value));this.check();
   return {status:deferred?'deferred':'stored',inserted};
  }
  async list(accountSlot,limit=32,after=null){
   this.check();if(!slot(accountSlot)||!Number.isInteger(limit)||limit<1||limit>128)throw Error('Invalid Inbox selector');
   if(after!==null&&(!Number.isSafeInteger(after.receivedAt)||after.receivedAt<0||!token(after.handle)))throw Error('Invalid Inbox cursor');
   const records=[];let unreadable=0,deferred=0;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    try{
     const value=await this.decrypt(row);
     if(value.accountSlot===accountSlot){if(value.kind==='pending')records.push({handle:row.key,...value});else if(value.kind==='deferred')deferred++;}
    }catch(error){this.check();unreadable++;}
   }
   records.sort((a,b)=>a.receivedAt-b.receivedAt||(a.handle<b.handle?-1:a.handle>b.handle?1:0));
   const remaining=after?records.filter(row=>row.receivedAt>after.receivedAt||(row.receivedAt===after.receivedAt&&row.handle>after.handle)):records;
   return {records:remaining.slice(0,limit),unreadable,deferred};
  }
  async acknowledge(handle,accountSlot,{guard=()=>true}={}){
   this.check();if(!guard())throw Error('Inbox owner session changed');if(!token(handle)||!slot(accountSlot))throw Error('Invalid Inbox receipt');
   const row=await this.store.read(handle);if(!row)return false;
   const value=await this.decrypt(row);
   if(value.accountSlot!==accountSlot)throw Error('Inbox Account mismatch');
   if(value.kind==='seen')return true;
   if(value.kind!=='pending')throw Error('Invalid Inbox state');
   // Caller sends this only after Account state/message persistence succeeds.
   return this.store.cas(handle,row.revision,await this.encrypt(handle,{kind:'seen',accountSlot,seenAt:this.clock()}),{guard});
  }
  async saveBinding(routeId,value,{replace=false}={}){
   this.check();if(!token(routeId))throw Error('Invalid local route');
   const key='binding:'+await this.alias('route|'+routeId),row=await this.store.read(key);
   if(row&&!replace)return false;
   return this.store.cas(key,row?.revision??null,await this.encrypt(key,{...value,kind:'binding',routeId}));
  }
  async bindings(){
   this.check();const records=[];let unreadable=0;
   for(const row of await this.store.allBindings()){
    if(row.key==='owner')continue;
    try{const value=await this.decrypt(row);if(value.kind!=='binding'||!token(value.routeId))throw Error();records.push(value);}
    catch(error){this.check();unreadable++;}
   }
   return {records,unreadable};
  }
  async pruneSeen(){
   this.check();let removed=0;const before=this.clock()-30*86400000;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    let value;try{value=await this.decrypt(row);}catch(error){this.check();continue;}
    if(value.kind==='seen'&&value.seenAt<=before&&await this.store.cas(row.key,row.revision,null))removed++;
   }
   return removed;
  }
  async retryDeferred(routeId,accountSlot,privateKeys){
   this.check();if(!token(routeId)||!slot(accountSlot)||!Array.isArray(privateKeys)||!privateKeys.length)throw Error('Recipient keys required');
   let processed=0;
   for(const row of await this.store.all()){
    if(row.key==='owner')continue;
    let value;try{value=await this.decrypt(row);}catch(error){this.check();continue;}
    if(value.kind!=='deferred'||value.routeId!==routeId||value.accountSlot!==accountSlot)continue;
    const opened=global.DmashRecipientPayloadV4.openPayload(privateKeys,value.blob);
    if(opened.status==='discard'){if(await this.store.cas(row.key,row.revision,null))processed++;continue;}
    if(opened.status!=='accepted')continue;
    const targetKey=await this.alias('packet|'+routeId+'|'+opened.packet_id),target=await this.store.read(targetKey);
    let preserve=false;
    if(target){
     let prior;try{prior=await this.decrypt(target);}catch(error){this.check();}
     if(prior){if(prior.accountSlot!==accountSlot)throw Error('Inbox Account mismatch');preserve=prior.kind==='pending'||prior.kind==='seen';}
    }
    const replacement=preserve?null:await this.encrypt(targetKey,{kind:'pending',routeId,accountSlot,receivedAt:value.receivedAt,packetId:opened.packet_id,payload:opened.payload});
    if(await this.store.promote(row.key,row.revision,targetKey,target?.revision??null,replacement))processed++;
   }
   return processed;
  }
  close(){this.closed=true;this.store?.close();this.aliasKey=null;this.encryptionKey=null;}
 }
 global.DmashNodeInboxV4=NodeInboxV4;global.DmashNodeInboxStoreV4=InboxStore;
 if(typeof module!=='undefined')module.exports={NodeInboxV4,InboxStore};
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const hex=value=>Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
 const unhex=value=>{if(typeof value!=='string'||!/^[0-9a-f]{64}$/.test(value))throw Error('Invalid local key');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const key=value=>{if(!(value instanceof Uint8Array)||value.length!==32)throw Error('Invalid local key');return value.slice();};
 const wipe=entry=>{entry?.sign?.secretKey.fill(0);entry?.box?.secretKey.fill(0);for(const k of entry?.recipientKeys||[])k.fill(0);};
 class LocalDeliveryV4{
  constructor(runtime,inbox){this.runtime=runtime;this.inbox=inbox;this.bindings=new Map();this.busy=new Set();this.routes=new Map();this.pending=0;this.discoveries=new Map();this.closed=false;}
  check(){if(this.closed)throw Error('Local Node closed');this.inbox.check();}
  async bind(data,{persist=true}={}){
   this.check();const certificate={...data.certificate},id=certificate.route_id;
   global.DmashRouteDiscoveryV4.verifyCertificate(certificate);
   if(typeof data.accountSlot!=='string'||!data.accountSlot||data.accountSlot.length>512)throw Error('Invalid local Account slot');
   if(this.busy.has(id)||this.bindings.has(id)||this.bindings.size+this.busy.size>=32)throw Error('Local route unavailable');
   this.busy.add(id);let entry,seed,boxSeed;
   try{
    seed=key(data.discoverySeed);boxSeed=key(data.discoveryBox);
    entry={certificate,accountSlot:data.accountSlot,ownership:data.ownership||null,retired:false,sign:nacl.sign.keyPair.fromSeed(seed),box:nacl.box.keyPair.fromSecretKey(boxSeed),recipientKeys:[]};
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length>2)throw Error('Invalid recipient keys');
    for(const value of data.recipientKeys)entry.recipientKeys.push(key(value));
    if(hex(entry.sign.publicKey)!==certificate.discovery_sign||hex(entry.box.publicKey)!==certificate.discovery_box)throw Error('Discovery key mismatch');
    this.validateRecipient(entry,entry.recipientKeys);
    const saved={certificate,accountSlot:data.accountSlot,discoverySeed:hex(seed),discoveryBox:hex(boxSeed),recipientKeys:entry.recipientKeys.map(hex)};
    if(persist&&!await this.inbox.saveBinding(id,saved))throw Error('Local route already persisted');
    this.check();
    const binding=entry;
    entry.handler=async(_,packet)=>{this.check();if(binding.retired)throw Error('Binding retired');if(this.finalControl&&await this.finalControl(id,packet,binding.recipientKeys)){this.check();if(binding.retired)throw Error('Binding retired');return {control:true};}this.check();if(binding.retired)throw Error('Binding retired');return this.inbox.receive(id,binding.accountSlot,packet.payload,binding.recipientKeys);};
    this.runtime.bindLocal(certificate,entry.sign,entry.box,entry.handler);
    this.bindings.set(id,entry);entry=null;
    return {bound:true};
   }finally{this.busy.delete(id);seed?.fill(0);boxSeed?.fill(0);wipe(entry);}
  }
  validateRecipient(entry,keys){
   if(keys.length){const pair=nacl.box.keyPair.fromSecretKey(keys[0]);try{if(hex(pair.publicKey)!==entry.certificate.recipient_box)throw Error('Recipient key mismatch');}finally{pair.secretKey.fill(0);}}
  }
  async restore({managedOnly=false}={}){
   const stored=await this.inbox.bindings();let unavailable=stored.unreadable;
   for(const value of stored.records){
    if(managedOnly&&!value.ownership){unavailable++;continue;}
    if(value.ownership&&value.state!=='ACTIVE')continue;
    const material=[];const decode=value=>{const bytes=unhex(value);material.push(bytes);return bytes;};
    try{await this.bind({ownership:value.ownership,certificate:value.certificate,accountSlot:value.accountSlot,discoverySeed:decode(value.discoverySeed),discoveryBox:decode(value.discoveryBox),recipientKeys:value.recipientKeys.map(decode)},{persist:false});}
    catch(error){this.check();unavailable++;}
    finally{for(const bytes of material)bytes.fill(0);}
   }
   return {restored:this.bindings.size,unavailable};
  }
  async installRecipientKeys(id,values){
   this.check();const entry=this.bindings.get(id);
   if(entry?.ownership)throw Error('Managed binding requires explicit key migration');
   if(!entry||this.busy.has(id)||!Array.isArray(values)||values.length<1||values.length>2)throw Error('Local route unavailable');
   this.busy.add(id);const keys=[];let installed=false;
   try{
    for(const value of values)keys.push(key(value));this.validateRecipient(entry,keys);
    const saved={certificate:entry.certificate,accountSlot:entry.accountSlot,discoverySeed:hex(entry.sign.secretKey.subarray(0,32)),discoveryBox:hex(entry.box.secretKey),recipientKeys:keys.map(hex)};
    if(!await this.inbox.saveBinding(id,saved,{replace:true}))throw Error('Local route changed');
    this.check();for(const previous of entry.recipientKeys)previous.fill(0);
    entry.recipientKeys=keys;installed=true;
    const processed=await this.inbox.retryDeferred(id,entry.accountSlot,keys);return {installed:true,processed};
   }finally{this.busy.delete(id);if(!installed)for(const bytes of keys)bytes.fill(0);}
  }
  retireOwned(id){const entry=this.bindings.get(id);if(!entry)return;entry.retired=true;this.runtime.owned=this.runtime.owned.filter(row=>row.handler!==entry.handler);for(const [key,row]of this.runtime.labels||[])if(row.target===entry.handler)this.runtime.labels.delete(key);this.bindings.delete(id);wipe(entry);}
  prune(){for(const [id,row] of this.routes)if(row.route.expires_at<=this.runtime.clock()||this.runtime.peers.get(row.route.peer)!==row.route.channel)this.routes.delete(id);}
  async discover(certificate,{ownerToken=null}={}){
   this.check();this.prune();if(this.pending>=4||this.routes.size+this.pending>=128)throw Error('Local discovery quota');
   if(ownerToken!==null&&(typeof ownerToken!=='string'||!/^[0-9a-f]{64}$/.test(ownerToken)))throw Error('Invalid discovery owner');
   certificate={...certificate};const controller=new AbortController();this.discoveries.set(controller,ownerToken);this.pending++;
   try{
    const route=await this.runtime.discover(certificate,{signal:controller.signal});this.check();if(controller.signal.aborted)throw Error('Node discovery cancelled');
    const handle=hex(crypto.getRandomValues(new Uint8Array(32)));this.routes.set(handle,{route,certificate,ownerToken});
    return {handle,expiresAt:route.expires_at};
   }finally{this.discoveries.delete(controller);this.pending--;}
  }
  releaseGrant(handle,ownerToken){this.check();const row=this.routes.get(handle);if(!row)return false;if(!ownerToken||row.ownerToken!==ownerToken)throw Error('Discovery owner mismatch');this.routes.delete(handle);return true;}
  releaseOwnerGrants(ownerToken){this.check();if(typeof ownerToken!=='string'||!/^[0-9a-f]{64}$/.test(ownerToken))throw Error('Invalid discovery owner');for(const [controller,owner] of this.discoveries)if(owner===ownerToken)controller.abort();let released=0;for(const [handle,row] of this.routes)if(row.ownerToken===ownerToken){this.routes.delete(handle);released++;}return released;}
  async sendSealed(handle,blob,replyRouteId,certificateDigest,{guard=()=>true,ownerToken=null}={}){
   this.check();this.prune();const destination=this.routes.get(handle),reply=this.bindings.get(replyRouteId);
   if(!destination||!reply||typeof blob!=='string'||blob.length>21848||typeof certificateDigest!=='string'||!/^[0-9a-f]{64}$/.test(certificateDigest))throw Error('Invalid prepared recipient envelope');
   if(destination.ownerToken!==ownerToken)throw Error('Discovery owner mismatch');
   const raw=Uint8Array.from(atob(blob),c=>c.charCodeAt(0));if(raw.length<72||raw.length>16384||btoa(String.fromCharCode(...raw))!==blob)throw Error('Invalid prepared recipient encoding');
   global.DmashRouteDiscoveryV4.validateX25519PublicKey(hex(raw.subarray(0,32)));
   global.DmashRouteDiscoveryV4.verifyCertificate(destination.certificate);
   const expected=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(global.DmashSecureSession.canonical(destination.certificate)))));
   this.check();if(expected!==certificateDigest||!guard()||reply.retired)throw Error('Prepared recipient target changed');
   this.runtime.send(destination.route,blob,reply.handler);return {queued:true,certificateDigest};
  }
  send(handle,payload,replyRouteId,ownerToken=null){
   this.check();this.prune();const destination=this.routes.get(handle),reply=this.bindings.get(replyRouteId);
   if(!destination||!reply)throw Error('Local route unavailable');
   if(destination.ownerToken!==ownerToken)throw Error('Discovery owner mismatch');
   global.DmashRouteDiscoveryV4.verifyCertificate(destination.certificate);
   this.runtime.send(destination.route,global.DmashRecipientPayloadV4.sealPayload(unhex(destination.certificate.recipient_box),payload),reply.handler);
   return {queued:true};
  }
  close(){this.closed=true;for(const controller of this.discoveries.keys())controller.abort();this.discoveries.clear();for(const entry of this.bindings.values())wipe(entry);this.bindings.clear();this.routes.clear();}
 }
 global.DmashNodeLocalDeliveryV4=LocalDeliveryV4;
 if(typeof module!=='undefined')module.exports=LocalDeliveryV4;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
// Worker-local authority. No Account secret enters this module; owner signatures
// are local registration proofs, never sent on the mesh.
(function(g){
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Invalid commitment');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));},canonical=v=>g.DmashSecureSession.canonical(v),digest=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(v)))));
 class Ownership{
  constructor(local,inbox){this.local=local;this.inbox=inbox;this.challenges=new Map();this.owners=new Map();this.busy=new Set();this.closed=false;}
  check(){if(this.closed)throw Error('Local ownership closed');this.local.check();}
  async challenge(accountPublic,certificate,{archive=false}={}){
   this.check();g.DmashRouteDiscoveryV4.validateEd25519PublicEncoding(accountPublic);
   if(archive){if(!Number.isSafeInteger(certificate?.expires_at)||certificate.expires_at>Math.floor(Date.now()/1000))throw Error('Archive requires expired certificate');g.DmashRouteDiscoveryV4.verifyCertificate(certificate,certificate.expires_at-1);}else g.DmashRouteDiscoveryV4.verifyCertificate(certificate);
   for(const [id,v]of this.challenges)if(v.expires<=Date.now())this.challenges.delete(id);
   if(this.challenges.size>=16)throw Error('Owner challenge quota');
   const id=hex(crypto.getRandomValues(new Uint8Array(32))),routeAuthorityDigest=await digest(certificate),ownerSlot=await this.inbox.alias('local-account-owner-v4|'+accountPublic);
   if(archive){const expected={accountPublic,ownerSlot,routeAuthorityDigest,routeId:certificate.route_id};let row=await this.read(certificate.route_id);if(!row?.ownership&&this.archiveRowProvider)row=await this.archiveRowProvider(expected);if(!row?.ownership||row.ownership.accountPublic!==accountPublic||row.ownership.ownerSlot!==ownerSlot||row.ownership.routeAuthorityDigest!==routeAuthorityDigest||await digest(row.certificate)!==routeAuthorityDigest)throw Error('Existing archived owner required');}
   const proof={...(archive?{archive:true}:{}),domain:'D-MASH|LOCAL-OWNER|V4',nodeId:this.inbox.localId,accountPublic,ownerSlot,routeAuthorityDigest,routeId:certificate.route_id,challenge:id,expires:Date.now()+60000};
   this.check();this.challenges.set(id,proof);return {challenge:id,transcript:canonical(proof)};
  }
  async register(challenge,signature){
   this.check();const proof=this.challenges.get(challenge);this.challenges.delete(challenge);
   if(!proof||proof.expires<=Date.now()||this.owners.size>=64)throw Error('Owner challenge unavailable');
   if(!(signature instanceof Uint8Array)||signature.length!==64)throw Error('Owner signature required');
   g.DmashRouteDiscoveryV4.validateEd25519SignatureEncoding(hex(signature));
   if(!nacl.sign.detached.verify(new TextEncoder().encode(canonical(proof)),signature,unhex(proof.accountPublic)))throw Error('Owner proof rejected');
   const token=hex(crypto.getRandomValues(new Uint8Array(32))),value={...(proof.archive?{archive:true}:{}),accountPublic:proof.accountPublic,ownerSlot:proof.ownerSlot,routeAuthorityDigest:proof.routeAuthorityDigest,routeId:proof.routeId};
   this.owners.set(token,value);return {token,...value,accountPublic:proof.accountPublic};
  }
  owner(token,{archiveAllowed=false}={}){this.check();const value=this.owners.get(token);if(!value)throw Error('Owner capability unavailable');if(value.archive&&!archiveAllowed)throw Error('Archive capability is read/drain only');return value;}
  async read(routeId){const key='binding:'+await this.inbox.alias('route|'+routeId),row=await this.inbox.store.read(key);return row?await this.inbox.decrypt(row):null;}
  matches(value,owner){if(!value?.ownership||value.ownership.ownerSlot!==owner.ownerSlot||value.ownership.routeAuthorityDigest!==owner.routeAuthorityDigest)throw Error('Owner tuple mismatch');}
  async prepare(token,data){try{return await this.prepareInner(token,data);}finally{for(const bytes of [data?.discoverySeed,data?.discoveryBox,...(Array.isArray(data?.recipientKeys)?data.recipientKeys:[])])bytes?.fill?.(0);}}
  async prepareInner(token,data){
   const owner=this.owner(token);for(const v of [data.migrationId,data.bindingDigest])unhex(v);
   if(!Number.isSafeInteger(data.expectedGeneration)||data.expectedGeneration<1||data.expectedGeneration!==data.certificate?.generation)throw Error('Invalid generation');
   if(this.busy.has(owner.routeId))throw Error('Binding mutation pending');this.busy.add(owner.routeId);
   let sign,box;
   try{
    g.DmashRouteDiscoveryV4.verifyCertificate(data.certificate);
    if(await digest(data.certificate)!==owner.routeAuthorityDigest)throw Error('Route authority changed');
    for(const bytes of [data.discoverySeed,data.discoveryBox,...data.recipientKeys])if(!(bytes instanceof Uint8Array)||bytes.length!==32)throw Error('Invalid private material');
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length<1||data.recipientKeys.length>2)throw Error('Recipient quota');
    sign=nacl.sign.keyPair.fromSeed(data.discoverySeed);box=nacl.box.keyPair.fromSecretKey(data.discoveryBox);
    if(hex(sign.publicKey)!==data.certificate.discovery_sign||hex(box.publicKey)!==data.certificate.discovery_box)throw Error('Route private authority mismatch');
    this.local.validateRecipient({certificate:data.certificate},data.recipientKeys);
    const tuple={...owner,migrationId:data.migrationId,bindingDigest:data.bindingDigest,generation:data.expectedGeneration};
    tuple.preparationDigest=await digest(tuple);
    const previous=await this.read(owner.routeId);
    if(previous){this.matches(previous,owner);if(canonical(previous.ownership)!==canonical(tuple))throw Error('Binding transaction conflict');return {...tuple,state:previous.state};}
    const saved={certificate:{...data.certificate},accountSlot:owner.ownerSlot,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex),ownership:tuple,state:'NODE_PREPARED'};
    this.owner(token);if(!await this.inbox.saveBinding(owner.routeId,saved))throw Error('Binding CAS conflict');return {...tuple,state:saved.state};
   }finally{this.busy.delete(owner.routeId);sign?.secretKey.fill(0);box?.secretKey.fill(0);for(const bytes of [data.discoverySeed,data.discoveryBox,...(data.recipientKeys||[])])bytes?.fill?.(0);}
  }
  async query(token,migrationId){const owner=this.owner(token,{archiveAllowed:true}),row=await this.read(owner.routeId);if(!row)return null;this.matches(row,owner);if(row.ownership.migrationId!==migrationId)throw Error('Migration mismatch');return {...row.ownership,state:row.state};}
  async change(token,tuple,state){
   const owner=this.owner(token);if(this.busy.has(owner.routeId))throw Error('Binding mutation pending');this.busy.add(owner.routeId);
   try{
    const row=await this.read(owner.routeId);this.matches(row,owner);
    if(canonical(row.ownership)!==canonical(tuple))throw Error('Prepared tuple mismatch');
    if(row.state===state){if(state==='ACTIVE'&&!this.local.bindings.has(owner.routeId))await this.activateSaved(row);return {...tuple,state};}
    if(state==='ACTIVE'&&row.state!=='NODE_PREPARED'||state==='RETIRED'&&row.state!=='ACTIVE')throw Error('Invalid binding transition');
    const changed={...row,state,...(state==='ACTIVE'?{activatedAt:Math.floor(Date.now()/1000)}:{})};this.owner(token);if(!await this.inbox.saveBinding(owner.routeId,changed,{replace:true}))throw Error('Binding CAS conflict');
    if(state==='ACTIVE'){
     await this.activateSaved(changed);
    }else this.local.retireOwned(owner.routeId);
    return {...tuple,state};
   }finally{this.busy.delete(owner.routeId);}
  }
  async activateSaved(row){if(this.detachBootstrap)await this.detachBootstrap(row.routeId);const material=[unhex(row.discoverySeed),unhex(row.discoveryBox),...row.recipientKeys.map(unhex)];try{await this.local.bind({...row,discoverySeed:material[0],discoveryBox:material[1],recipientKeys:material.slice(2)},{persist:false});}finally{for(const value of material)value.fill(0);}}
  close(){this.closed=true;this.challenges.clear();this.owners.clear();}
 }
 g.DmashNodeLocalOwnershipV4=Ownership;if(typeof module!=='undefined')module.exports=Ownership;
})(globalThis);

'use strict';
(function(global){
 const FIELDS=['type','version','transport_version','pairing_id','generation','issued_at','expires_at','previous_binding','intended_peer','contribution','account_keys','inbound_certificate','signature'];
 const KEYS=['signing','box','kem_profile','kem_public'];
 const CERT=['version','route_id','discovery_sign','discovery_box','recipient_box','generation','issued_at','expires_at','signature'];
 const MAX_BYTES=12288,PROFILE='LEGACY_KYBER768_BUNDLE_V1';
 const utf8=s=>new TextEncoder().encode(s);
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const hex=(s,n=32)=>{if(typeof s!=='string'||!new RegExp('^[0-9a-f]{'+n*2+'}$').test(s))fail('ENCODING');return Uint8Array.from(s.match(/../g),v=>parseInt(v,16));};
 const toHex=a=>Array.from(a,v=>v.toString(16).padStart(2,'0')).join('');
 const integer=n=>{if(!Number.isSafeInteger(n)||n<0||Object.is(n,-0))fail('INTEGER');};
 function exact(o,fields){
  if(!o||typeof o!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(o)))fail('SCHEMA');
  const names=Reflect.ownKeys(o);if(names.length!==fields.length||names.some(k=>!fields.includes(k)))fail('SCHEMA');
  for(const k of names)if(!Object.hasOwn(Object.getOwnPropertyDescriptor(o,k),'value'))fail('SCHEMA');
 }
 function ordered(o,fields){return Object.fromEntries(fields.map(k=>[k,o[k]]));}
 function canonical(value,withSignature=true){
  exact(value,FIELDS);exact(value.account_keys,KEYS);exact(value.inbound_certificate,CERT);
  for(const [object,fields] of [[value,FIELDS.filter(k=>!['account_keys','inbound_certificate'].includes(k))],[value.account_keys,KEYS],[value.inbound_certificate,CERT]])
   for(const k of fields){if(object[k]!==null&&!['string','number'].includes(typeof object[k]))fail('SCHEMA');if(typeof object[k]==='string'&&object[k].length>MAX_BYTES)fail('SIZE');}
  const o=ordered(value,withSignature?FIELDS:FIELDS.slice(0,-1));
  o.account_keys=ordered(value.account_keys,KEYS);o.inbound_certificate=ordered(value.inbound_certificate,CERT);
  return JSON.stringify(o);
 }
 function schema(b){
  canonical(b);
  if(b.type!=='DMASH_PAIRING_V2'||b.version!==2||b.transport_version!==4)fail('UPGRADE_REQUIRED_V2');
  hex(b.pairing_id);hex(b.contribution);hex(b.signature,64);
  for(const k of ['generation','issued_at','expires_at'])integer(b[k]);
  if(b.generation<1||b.expires_at<=b.issued_at||b.expires_at-b.issued_at>86400)fail('VALIDITY');
  if(b.previous_binding!==null)hex(b.previous_binding);if(b.intended_peer!==null)hex(b.intended_peer);
  const a=b.account_keys,c=b.inbound_certificate;
  hex(a.signing);hex(a.box);
  if(![PROFILE,'ACCOUNT_STATIC_LEGACY_KYBER768_V1'].includes(a.kem_profile))fail('PROFILE');
  if(typeof a.kem_public!=='string'||!/^[A-Za-z0-9_-]{1579}$/.test(a.kem_public))fail('KEM_ENCODING');
  const raw=atob(a.kem_public.replace(/-/g,'+').replace(/_/g,'/')+'=');
  if(raw.length!==1184||btoa(raw).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==a.kem_public)fail('KEM_ENCODING');
  for(const k of ['route_id','discovery_sign','discovery_box','recipient_box'])hex(c[k]);
  hex(c.signature,64);for(const k of ['generation','issued_at','expires_at'])integer(c[k]);
  if(c.version!==4||c.generation!==b.generation||c.expires_at<b.expires_at)fail('CERTIFICATE_CONTEXT');
  const roles=[a.signing,a.box,c.route_id,c.discovery_sign,c.discovery_box,c.recipient_box];
  if(new Set(roles).size!==roles.length)fail('KEY_ROLE_REUSE');
 }
 function createCodec({nacl,discovery}){
  if(!nacl?.sign?.detached?.verify||!discovery?.verifyCertificate||!discovery?.validateEd25519PublicEncoding||!discovery?.validateEd25519SignatureEncoding||!discovery?.validateX25519PublicKey)fail('DEPENDENCY');
  function transcript(b){schema(b);const body=utf8(canonical(b,false)),out=new Uint8Array(utf8('D-MASH|ACCOUNT-PAIRING|V2\0').length+4+body.length),prefix=utf8('D-MASH|ACCOUNT-PAIRING|V2\0');out.set(prefix);new DataView(out.buffer).setUint32(prefix.length,body.length);out.set(body,prefix.length+4);return out;}
  function verify(b,context={}){
   // Copy before cryptographic checks: callers cannot mutate the returned candidate.
   schema(b);const serialized=canonical(b);if(utf8(serialized).length>MAX_BYTES)fail('SIZE');b=JSON.parse(serialized);schema(b);
   const now=context.now??Math.floor(Date.now()/1000);integer(now);
   if(b.issued_at>now+60||b.expires_at<=now)fail('EXPIRED');
   for(const key of [b.account_keys.signing,b.inbound_certificate.route_id,b.inbound_certificate.discovery_sign])discovery.validateEd25519PublicEncoding(key);
   discovery.validateEd25519SignatureEncoding(b.signature);discovery.validateEd25519SignatureEncoding(b.inbound_certificate.signature);
   if(!nacl.sign.detached.verify(transcript(b),hex(b.signature,64),hex(b.account_keys.signing)))fail('ACCOUNT_SIGNATURE');
   discovery.verifyCertificate(b.inbound_certificate,now);
   discovery.validateX25519PublicKey(b.account_keys.box);
   if(context.expectedPeer!==undefined){hex(context.expectedPeer);if(b.account_keys.signing!==context.expectedPeer)fail('IDENTITY_MISMATCH');}
   if(context.localAccount!==undefined){hex(context.localAccount);if(b.account_keys.signing===context.localAccount)fail('SELF_PAIRING');}
   if(b.intended_peer!==null&&b.intended_peer!==context.localAccount)fail('TARGET_MISMATCH');
   if(context.expectedGeneration!==undefined){integer(context.expectedGeneration);if(b.generation!==context.expectedGeneration)fail('GENERATION_MISMATCH');}
   if(Object.hasOwn(context,'previousBinding')){if(context.previousBinding!==null)hex(context.previousBinding);if(b.previous_binding!==context.previousBinding)fail('PREDECESSOR_MISMATCH');}
   Object.freeze(b.account_keys);Object.freeze(b.inbound_certificate);Object.freeze(b);
   return Object.freeze({bundle:b,serialized,identityStatus:context.expectedPeer===undefined?'UNPINNED_CANDIDATE':'PINNED_CANDIDATE'});
  }
  function parse(input,context){
   if(typeof input!=='string')fail('ENCODING');if(input.length>MAX_BYTES||utf8(input).length>MAX_BYTES)fail('SIZE');
   let b;try{b=JSON.parse(input);}catch{fail('JSON');}
   if(b?.type==='DMASH_PAIRING_V1'||b?.version===1)fail('UPGRADE_REQUIRED_V2');
   if(canonical(b)!==input)fail('NON_CANONICAL');return verify(b,context);
  }
  function sign(body,secretKey,context){
   exact(body,FIELDS.slice(0,-1));
   const b={...body,signature:'00'.repeat(64)};schema(b);
   if(!(secretKey instanceof Uint8Array)||secretKey.length!==64||toHex(nacl.sign.keyPair.fromSecretKey(secretKey).publicKey)!==b.account_keys.signing)fail('SIGNER_MISMATCH');
   b.signature=toHex(nacl.sign.detached(transcript(b),secretKey));return verify(b,context);
  }
  return Object.freeze({parse,verify,sign,transcript});
 }
 const api=Object.freeze({createCodec,MAX_BYTES,PROFILE});global.DmashAccountPairingV2=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
(function(global){
 const RECEIPT_FIELDS=['type','version','phase','binding_digest','signer','signature'];
 const CERT_FIELDS=['version','route_id','discovery_sign','discovery_box','recipient_box','generation','issued_at','expires_at','signature'];
 const MAX_BINDING=4096,MAX_RECEIPT=2048,MAX_BUNDLE=12288;
 const text=value=>new TextEncoder().encode(value);
 const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 const fail=code=>{throw Object.assign(new Error(code),{code});};
 const unhex=(value,size=32)=>{if(typeof value!=='string'||!new RegExp('^[0-9a-f]{'+size*2+'}$').test(value))fail('ENCODING');return Uint8Array.from(value.match(/../g),b=>parseInt(b,16));};
 const integer=value=>{if(!Number.isSafeInteger(value)||value<0||Object.is(value,-0))fail('INTEGER');};
 const join=(a,b)=>{const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;};
 function exact(value,keys){
  if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('SCHEMA');
  const actual=Reflect.ownKeys(value);
  if(actual.length!==keys.length||actual.some(k=>!keys.includes(k)))fail('SCHEMA');
  for(const key of actual)if(!Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value'))fail('SCHEMA');
 }
 function participants(value){
  if(!Array.isArray(value)||value.length!==2)fail('PARTICIPANTS');
  const copy=value.map(key=>{unhex(key);return key;}).sort();
  if(copy[0]===copy[1])fail('SELF_PAIRING');return copy;
 }
 function committedSnapshot(value){
  if(value===null)return null;
  exact(value,['generation','binding_digest','participants']);integer(value.generation);
  if(value.generation<1)fail('GENERATION');unhex(value.binding_digest);
  return Object.freeze({generation:value.generation,binding_digest:value.binding_digest,participants:Object.freeze(participants(value.participants))});
 }
 function createBindingCodec({nacl,discovery,pairing,subtle=global.crypto?.subtle,clock=()=>Math.floor(Date.now()/1000)}){
  if(!nacl?.sign?.detached?.verify||!discovery?.validateEd25519SignatureEncoding||!discovery?.validateEd25519PublicEncoding||!pairing?.parse||!subtle?.digest)fail('DEPENDENCY');
  const prepared=new WeakMap();
  const now=()=>{const value=clock();integer(value);return value;};
  const digest=async bytes=>hex(new Uint8Array(await subtle.digest('SHA-256',bytes)));
  function current(candidate){const data=prepared.get(candidate);if(!data)fail('UNVERIFIED_BINDING');if(data.binding.expires_at<=now())fail('EXPIRED');return data;}
  function checkGeneration(data,committed){
   const binding=data.binding,ids=binding.participants.map(p=>p.account);
   if(committed===null){if(binding.generation!==1||binding.previous_binding!==null)fail('PREDECESSOR_REQUIRED');return 'BILATERAL_CANDIDATE';}
   if(ids.some((id,i)=>id!==committed.participants[i]))fail('IDENTITY_MISMATCH');
   if(binding.generation<committed.generation)fail('GENERATION_ROLLBACK');
   if(binding.generation===committed.generation){if(data.digest!==committed.binding_digest)fail('GENERATION_CONFLICT');return 'IDEMPOTENT_REPLAY';}
   if(binding.previous_binding!==committed.binding_digest)fail('PREDECESSOR_MISMATCH');
   return 'BILATERAL_CANDIDATE';
  }
  async function prepare(serializedBundles,context){
   if(!Array.isArray(serializedBundles)||serializedBundles.length!==2)fail('BUNDLES');
   if(!context||!Object.hasOwn(context,'committed'))fail('COMMITTED_CONTEXT_REQUIRED');
   const expected=participants(context.expectedParticipants),committed=committedSnapshot(context.committed),checkedAt=now();
   const verified=serializedBundles.map(serialized=>{
    if(typeof serialized!=='string'||serialized.length>MAX_BUNDLE||text(serialized).length>MAX_BUNDLE)fail('SIZE');
    let raw;try{raw=JSON.parse(serialized);}catch{fail('JSON');}
    const index=expected.indexOf(raw?.account_keys?.signing);if(index<0)fail('IDENTITY_MISMATCH');
    return pairing.parse(serialized,{now:checkedAt,expectedPeer:expected[index],localAccount:expected[1-index]});
   }).sort((a,b)=>a.bundle.account_keys.signing<b.bundle.account_keys.signing?-1:1);
   const [a,b]=verified.map(v=>v.bundle);
   if(a.account_keys.signing===b.account_keys.signing)fail('SELF_PAIRING');
   if(a.generation!==b.generation||a.previous_binding!==b.previous_binding)fail('BINDING_CONTEXT');
   if(a.account_keys.kem_profile!==b.account_keys.kem_profile)fail('PROFILE');
   if(a.generation>1&&(a.intended_peer===null||b.intended_peer===null))fail('TARGET_REQUIRED');
   if(a.account_keys.kem_public===b.account_keys.kem_public)fail('KEY_ROLE_REUSE');
   if(a.pairing_id===b.pairing_id||a.contribution===b.contribution)fail('DUPLICATE_OFFER');
   const roles=[a,b].flatMap(v=>[v.account_keys.signing,v.account_keys.box,v.inbound_certificate.route_id,v.inbound_certificate.discovery_sign,v.inbound_certificate.discovery_box,v.inbound_certificate.recipient_box]);
   if(new Set(roles).size!==roles.length)fail('KEY_ROLE_REUSE');
   const members=await Promise.all(verified.map(async v=>Object.freeze({
    account:v.bundle.account_keys.signing,
    bundle_digest:await digest(text(v.serialized)),
    contribution:v.bundle.contribution,
    certificate_digest:await digest(text(JSON.stringify(Object.fromEntries(CERT_FIELDS.map(k=>[k,v.bundle.inbound_certificate[k]])))))
   })));
   const binding=Object.freeze({type:'DMASH_ACCOUNT_ROUTE_BINDING_V2',version:2,transport_version:4,kem_profile:a.account_keys.kem_profile,generation:a.generation,previous_binding:a.previous_binding,participants:Object.freeze(members),expires_at:Math.min(a.expires_at,b.expires_at)});
   const serialized=JSON.stringify(binding);if(text(serialized).length>MAX_BINDING)fail('SIZE');
   const bindingDigest=await digest(join(text('D-MASH|ACCOUNT-ROUTE-BINDING|V2\0'),text(serialized)));
   // No mutable Account/root/storage authority is retained across these awaits.
   const finishedAt=now();for(const v of verified)pairing.parse(v.serialized,{now:finishedAt,expectedPeer:v.bundle.account_keys.signing,localAccount:expected.find(id=>id!==v.bundle.account_keys.signing)});
   const data={binding,digest:bindingDigest,serialized};checkGeneration(data,committed);
   const candidate=Object.freeze({binding,digest:bindingDigest,serialized,status:'UNSIGNED_CANDIDATE'});
   prepared.set(candidate,data);return candidate;
  }
  function receiptBody(receipt){return JSON.stringify(Object.fromEntries(RECEIPT_FIELDS.slice(0,-1).map(k=>[k,receipt[k]])));}
  function receiptTranscript(receipt){
   const body=text(receiptBody(receipt)),prefix=text('D-MASH|ACCOUNT-ROUTE-RECEIPT|V2|'+receipt.phase+'\0'),length=new Uint8Array(4);
   new DataView(length.buffer).setUint32(0,body.length);return join(join(prefix,length),body);
  }
  function verifyReceipt(candidate,serialized,phase){
   const data=current(candidate);
   if(typeof serialized!=='string'||serialized.length>MAX_RECEIPT||text(serialized).length>MAX_RECEIPT)fail('SIZE');
   let receipt;try{receipt=JSON.parse(serialized);}catch{fail('JSON');}
   exact(receipt,RECEIPT_FIELDS);
   const canonical=JSON.stringify(Object.fromEntries(RECEIPT_FIELDS.map(k=>[k,receipt[k]])));
   if(serialized!==canonical)fail('NON_CANONICAL');
   if(receipt.type!=='DMASH_ACCOUNT_ROUTE_RECEIPT_V2'||receipt.version!==2||!['ACCEPT','CONFIRM'].includes(receipt.phase))fail('RECEIPT_SCHEMA');
   if(phase!==undefined&&receipt.phase!==phase)fail('PHASE');
   unhex(receipt.binding_digest);unhex(receipt.signer);unhex(receipt.signature,64);
   const expected=data.binding.participants[receipt.phase==='ACCEPT'?0:1].account;
   if(receipt.signer!==expected||receipt.binding_digest!==data.digest)fail('RECEIPT_CONTEXT');
   discovery.validateEd25519PublicEncoding(receipt.signer);discovery.validateEd25519SignatureEncoding(receipt.signature);
   if(!nacl.sign.detached.verify(receiptTranscript(receipt),unhex(receipt.signature,64),unhex(receipt.signer)))fail('RECEIPT_SIGNATURE');
   return Object.freeze(receipt);
  }
  function signReceipt(candidate,phase,secretKey,acceptReceipt){
   const data=current(candidate);if(!['ACCEPT','CONFIRM'].includes(phase))fail('PHASE');
   if(phase==='CONFIRM')verifyReceipt(candidate,acceptReceipt,'ACCEPT');
   const signer=data.binding.participants[phase==='ACCEPT'?0:1].account;
   if(!(secretKey instanceof Uint8Array)||secretKey.length!==64||hex(nacl.sign.keyPair.fromSecretKey(secretKey).publicKey)!==signer)fail('SIGNER_MISMATCH');
   const receipt={type:'DMASH_ACCOUNT_ROUTE_RECEIPT_V2',version:2,phase,binding_digest:data.digest,signer,signature:''};
   receipt.signature=hex(nacl.sign.detached(receiptTranscript(receipt),secretKey));
   const serialized=JSON.stringify(receipt);verifyReceipt(candidate,serialized,phase);return serialized;
  }
  function verifyReceipts(candidate,receipts,context){
   const data=current(candidate);if(!context||!Object.hasOwn(context,'committed'))fail('COMMITTED_CONTEXT_REQUIRED');
   if(!Array.isArray(receipts)||receipts.length!==2)fail('BOTH_RECEIPTS_REQUIRED');
   const checked=receipts.map(receipt=>verifyReceipt(candidate,receipt));
   if(new Set(checked.map(r=>r.phase)).size!==2)fail('BOTH_RECEIPTS_REQUIRED');
   const status=checkGeneration(data,committedSnapshot(context.committed)),verifiedAt=now();
   if(data.binding.expires_at<=verifiedAt)fail('EXPIRED');
   return Object.freeze({status,binding:data.binding,digest:data.digest,verifiedAt,receipts:Object.freeze(['ACCEPT','CONFIRM'].map(phase=>receipts[checked.findIndex(r=>r.phase===phase)]))});
  }
  async function verifyCommitted(serializedBundles,receipts,context){
   // The caller must obtain this epoch from its authenticated durable journal.
   // This validates history only and never creates a currently signable candidate.
   integer(context?.verifiedAt);if(context.verifiedAt>now())fail('COMMIT_EPOCH_FUTURE');
   const historical=createBindingCodec({nacl,discovery,pairing,subtle,clock:()=>context.verifiedAt});
   const candidate=await historical.prepare(serializedBundles,context);
   return historical.verifyReceipts(candidate,receipts,context);
  }
  function compareCandidates(left,right){
   const a=current(left),b=current(right);
   if(a.binding.generation!==b.binding.generation||a.binding.previous_binding!==b.binding.previous_binding||a.binding.participants.some((p,i)=>p.account!==b.binding.participants[i].account))fail('INCOMPARABLE_CANDIDATES');
   for(let i=0;i<2;i++){const x=a.binding.participants[i].bundle_digest,y=b.binding.participants[i].bundle_digest;if(x!==y)return x<y?-1:1;}return 0;
  }
  return Object.freeze({prepare,signReceipt,verifyReceipt,verifyReceipts,verifyCommitted,compareCandidates});
 }
 const api=Object.freeze({createBindingCodec,MAX_BINDING,MAX_RECEIPT});global.DmashAccountRouteBindingV2=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window!=='undefined'?window:globalThis);

'use strict';
// Local recipient control parser. No Account private key is retained; no transit
// path calls this parser. REQUEST identity remains a candidate until selection.
(function(g){
 const text=v=>new TextEncoder().encode(v),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Invalid bootstrap digest');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const fields=['type','version','exchange_id','target_bundle_digest','bundle','accept_receipt','expires_at','signature'];
 const canonical=v=>g.DmashSecureSession.canonical(v),hash=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(v))));
 // Exact envelope expansion, including JSON escaping, is checked BEFORE mining.
 function fits(payload){if(typeof payload!=='string')throw Error('Bootstrap payload required');const envelope=JSON.stringify({type:'RECIPIENT_PAYLOAD',version:2,packet_id:'0'.repeat(64),payload});if(text(envelope).length+72>16384)throw Error('Bootstrap recipient envelope too large');return payload;}
 function createCodec({pairing,binding,discovery=g.DmashRouteDiscoveryV4,clock=()=>Math.floor(Date.now()/1000)}){
  const verified=new WeakMap();
  function exact(v){if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==[...fields].sort().join(','))throw Error('Bootstrap REQUEST schema');}
  const signedBytes=body=>text('D-MASH|NODE-BOOTSTRAP-REQUEST|V4\0'+canonical(body));
  async function inspect(localBundle,serialized){
   fits(serialized);const request=JSON.parse(serialized);exact(request);if(canonical(request)!==serialized)throw Error('Noncanonical bootstrap REQUEST');
   const now=clock();if(request.type!=='NODE_BOOTSTRAP_REQUEST_V4'||request.version!==4||!Number.isSafeInteger(request.expires_at)||request.expires_at<=now||request.expires_at>now+86400)throw Error('Bootstrap REQUEST expiry/profile');
   unhex(request.exchange_id);unhex(request.target_bundle_digest);
   if(await hash(localBundle)!==request.target_bundle_digest)throw Error('Wrong bootstrap target');
   const local=pairing.parse(localBundle,{now}),localAccount=local.bundle.account_keys.signing;
   const remote=pairing.parse(request.bundle,{now,localAccount}),remoteAccount=remote.bundle.account_keys.signing;
   if(request.expires_at>Math.min(local.bundle.expires_at,remote.bundle.expires_at))throw Error('Bootstrap request outlives offer');
   if(local.bundle.generation!==1||remote.bundle.generation!==1)throw Error('Existing-contact recovery requires separate authority');
   const {signature,...body}=request;discovery.validateEd25519SignatureEncoding(signature);
   if(!g.nacl.sign.detached.verify(signedBytes(body),Uint8Array.from(signature.match(/../g),x=>parseInt(x,16)),unhex(remoteAccount)))throw Error('Bootstrap REQUEST signature');
   const candidate=await binding.prepare([localBundle,request.bundle],{expectedParticipants:[localAccount,remoteAccount],committed:null});
   if(remote.bundle.intended_peer!==localAccount)throw Error('Requester bundle must target local offer owner');
   if(remoteAccount<localAccount&&request.accept_receipt===null)throw Error('Lower requester must include durable ACCEPT receipt');
   if(request.accept_receipt!==null){if(remoteAccount>localAccount)throw Error('Premature receipt phase');binding.verifyReceipt(candidate,request.accept_receipt,'ACCEPT');}
   const result=Object.freeze({exchangeId:request.exchange_id,requestDigest:await hash(serialized),bindingDigest:candidate.digest,localAccount,remoteAccount,expiresAt:request.expires_at,identityStatus:'UNSELECTED_CANDIDATE'});
   verified.set(result,{request,candidate,localBundle});return result;
  }
  async function request(localTargetBundle,senderBundle,exchangeId,secretKey,{acceptReceipt=null,expiresAt}={}){
   const target=pairing.parse(localTargetBundle,{now:clock()}),sender=pairing.parse(senderBundle,{now:clock(),localAccount:target.bundle.account_keys.signing});
   const signer=g.nacl.sign.keyPair.fromSecretKey(secretKey);try{if(hex(signer.publicKey)!==sender.bundle.account_keys.signing)throw Error('Request signer mismatch');}finally{signer.secretKey.fill(0);}
   const body={type:'NODE_BOOTSTRAP_REQUEST_V4',version:4,exchange_id:exchangeId,target_bundle_digest:await hash(localTargetBundle),bundle:senderBundle,accept_receipt:acceptReceipt,expires_at:expiresAt??Math.min(target.bundle.expires_at,sender.bundle.expires_at)};
   const wire=fits(canonical({...body,signature:hex(g.nacl.sign.detached(signedBytes(body),secretKey))}));await inspect(localTargetBundle,wire);return wire;
  }
  function receipt(handle,serialized,phase){const state=verified.get(handle);if(!state||handle.expiresAt<=clock())throw Error('Bootstrap candidate unavailable');if(typeof serialized!=='string'||text(serialized).length>2048)throw Error('Bootstrap receipt size');const value=binding.verifyReceipt(state.candidate,serialized,phase);return Object.freeze({...value});}
  async function localOffer(serialized,owner){
   if(typeof serialized!=='string'||text(serialized).length>12288)throw Error('Bootstrap bundle size');
   const raw=JSON.parse(serialized),checked=pairing.parse(serialized,{now:clock(),expectedPeer:owner.accountPublic,localAccount:raw.intended_peer??undefined});
   if(checked.bundle.inbound_certificate.route_id!==owner.routeId||await hash(canonical(checked.bundle.inbound_certificate))!==owner.routeAuthorityDigest)throw Error('Bootstrap local certificate authority mismatch');
   return Object.freeze({expiresAt:checked.bundle.expires_at});
  }
  return Object.freeze({inspect,request,receipt,localOffer,fits});
 }
 g.DmashNodeBootstrapControlV4=Object.freeze({createCodec,fits});if(typeof module!=='undefined')module.exports=g.DmashNodeBootstrapControlV4;
})(globalThis);

'use strict';
// Separate encrypted local control journal. Caller supplies the genuine local
// Ownership registry and a separately domain-keyed NodeInbox storage instance.
(function(g){
 const text=x=>new TextEncoder().encode(x),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 class Dispatcher{
  #tail=Promise.resolve();
  constructor({ownership,inbox,codec,clock=()=>Math.floor(Date.now()/1000)}){this.ownership=ownership;this.inbox=inbox;this.codec=codec;this.clock=clock;this.closed=false;}
  check(token,options){if(this.closed)throw Error('Bootstrap closed');this.inbox.check();return this.ownership.owner(token,options);}
  run(fn){const task=this.#tail.then(fn);this.#tail=task.catch(()=>{});return task;}
  async key(kind,owner,id=''){return this.inbox.alias('bootstrap-v4|'+kind+'|'+owner.ownerSlot+'|'+owner.routeId+'|'+id);}
  async load(key){const row=await this.inbox.store.read(key);return row?{row,value:await this.inbox.decrypt(row)}:null;}
  async save(token,key,previous,value){const encrypted=await this.inbox.encrypt(key,value);this.check(token);if(!await this.inbox.store.cas(key,previous?.row.revision??null,encrypted,{guard:()=>{this.check(token);return true;}}))throw Error('Bootstrap journal conflict');}
  register(token,localBundle){return this.run(async()=>{const owner=this.check(token);await this.codec.localOffer(localBundle,owner);
   const key=await this.key('config',owner),old=await this.load(key);if(old){if(old.value.localBundle!==localBundle)throw Error('Bootstrap renewal requires explicit migration');return true;}
   await this.save(token,key,null,{kind:'bootstrap-config',ownerSlot:owner.ownerSlot,routeId:owner.routeId,localBundle});return true;});}
  request(token,serialized,{targetBundle=null,outbound=false}={}){return this.run(async()=>{const owner=this.check(token),config=await this.load(await this.key('config',owner));if(!config)throw Error('Bootstrap not provisioned');
   if(outbound&&JSON.parse(serialized).bundle!==config.value.localBundle)throw Error('Outbound request not owned by local bundle');
   if(!outbound&&targetBundle!==null)throw Error('Unexpected target override');
   const target=outbound?targetBundle:config.value.localBundle;
   const verified=await this.codec.inspect(target,serialized),key=await this.key('request',owner,verified.exchangeId),old=await this.load(key);
   if(old){if(old.value.requestDigest!==verified.requestDigest)throw Error('Conflicting bootstrap replay');this.check(token);return {state:old.value.state,duplicate:true,requestDigest:verified.requestDigest};}
   let count=0,localCount=0,bytes=0;
   for(const row of await this.inbox.store.all()){
    let value;try{value=await this.inbox.decrypt(row);}catch(_){this.check(token);continue;}if(value.kind!=='bootstrap-request')continue;
    if(value.expiresAt<=this.clock()&&value.state!=='SELECTED'){this.check(token);await this.inbox.store.cas(row.key,row.revision,null,{guard:()=>{this.check(token);return true;}});continue;}
    count++;if(value.ownerSlot===owner.ownerSlot)localCount++;bytes+=text(value.serialized||'').length;
   }
   if(count>=32||localCount>=8||bytes+text(serialized).length>128*1024)throw Error('Bootstrap pending quota');
   const initial=JSON.parse(serialized).accept_receipt;
   await this.save(token,key,null,{kind:'bootstrap-request',ownerSlot:owner.ownerSlot,routeId:owner.routeId,exchangeId:verified.exchangeId,requestDigest:verified.requestDigest,bindingDigest:verified.bindingDigest,remoteAccount:verified.remoteAccount,expiresAt:verified.expiresAt,state:outbound?'SELECTED':'PENDING',direction:outbound?'OUTBOUND':'INBOUND',targetBundle:outbound?target:null,serialized,receipts:initial?{ACCEPT:initial}:{}});
   return {state:outbound?'SELECTED':'PENDING',duplicate:false,requestDigest:verified.requestDigest};});}
  select(token,exchangeId,requestDigest,{deny=false}={}){return this.run(async()=>{const owner=this.check(token),key=await this.key('request',owner,exchangeId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.expiresAt<=this.clock())throw Error('Bootstrap selection mismatch');
   if(old.value.state==='DENIED')throw Error('Bootstrap request denied');
   await this.save(token,key,old,{...old.value,state:deny?'DENIED':'SELECTED',...(deny?{serialized:null,receipts:{}}:{})});return {state:deny?'DENIED':'SELECTED'};});}
  receipt(token,exchangeId,serialized){return this.run(async()=>{const owner=this.check(token),key=await this.key('request',owner,exchangeId),old=await this.load(key);if(!old||old.value.state!=='SELECTED'||old.value.expiresAt<=this.clock())throw Error('Explicit bootstrap selection required');
   const config=await this.load(await this.key('config',owner)),candidate=await this.codec.inspect(old.value.targetBundle||config.value.localBundle,old.value.serialized),verified=this.codec.receipt(candidate,serialized),phase=verified.phase;
   const previous=old.value.receipts[phase];if(previous){if(previous!==serialized)throw Error('Conflicting receipt replay');return {stored:true,duplicate:true};}
   if(phase==='CONFIRM'&&!old.value.receipts.ACCEPT)throw Error('ACCEPT receipt required first');
   const receipts={...old.value.receipts,[phase]:serialized};if(Object.keys(receipts).length>2||Object.values(receipts).reduce((n,v)=>n+text(v).length,0)>8192)throw Error('Bootstrap control quota');
   await this.save(token,key,old,{...old.value,receipts});return {stored:true,duplicate:false,receiptsComplete:!!receipts.ACCEPT&&!!receipts.CONFIRM};});}
  list(token){return this.run(async()=>{const owner=this.check(token,{archiveAllowed:true}),values=[];for(const row of await this.inbox.store.all()){let value;try{value=await this.inbox.decrypt(row);}catch(_){this.check(token,{archiveAllowed:true});continue;}if(value.kind==='bootstrap-request'&&value.ownerSlot===owner.ownerSlot&&value.routeId===owner.routeId&&(value.expiresAt>this.clock()||value.state==='SELECTED'))values.push(value.expiresAt<=this.clock()?{...value,state:'EXPIRED_SELECTED'}:value);}this.check(token,{archiveAllowed:true});return values;});}
  close(){this.closed=true;this.inbox.close();}
 }
 g.DmashNodeBootstrapDispatcherV4=Dispatcher;if(typeof module!=='undefined')module.exports=Dispatcher;
})(globalThis);

'use strict';
(function(g){
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),decode=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Bootstrap key encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 class BootstrapRuntime{
  #roots=new Map();#routes=new Map();
  static async open(storageKey,nodeId,{runtime,ownership,local,isCurrent}){
   const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']),key=new Uint8Array(await crypto.subtle.sign('HMAC',base,new TextEncoder().encode('D-MASH|NODE-BOOTSTRAP|V4|STORAGE')));
   let inbox;try{inbox=await g.DmashNodeInboxV4.open(key,nodeId,{databaseName:'dmash_node_bootstrap_v4',maxRecords:96,maxBytes:1024*1024,isCurrent});}finally{key.fill(0);}
   const result=new BootstrapRuntime();Object.assign(result,{runtime,ownership,local,inbox,isCurrent,closed:false});
   const pairing=g.DmashAccountPairingV2.createCodec({nacl,discovery:g.DmashRouteDiscoveryV4}),binding=g.DmashAccountRouteBindingV2.createBindingCodec({nacl,discovery:g.DmashRouteDiscoveryV4,pairing});
   result.codec=g.DmashNodeBootstrapControlV4.createCodec({pairing,binding});
   result.dispatcher=new g.DmashNodeBootstrapDispatcherV4({ownership:{owner:(token,options)=>{result.check();return result.#roots.get(token)||ownership.owner(token,options);}},inbox,codec:result.codec});
   try{await result.restore();return result;}catch(error){result.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Bootstrap root closed');this.inbox.check();}
  async provision(token,data){
   let sign,box;const material=[data.discoverySeed,data.discoveryBox,...(Array.isArray(data.recipientKeys)?data.recipientKeys:[])];
   try{
    const owner=this.ownership.owner(token);const final=await this.ownership.read(owner.routeId);this.ownership.owner(token);if(final&&['ACTIVE','RETIRED'].includes(final.state))throw Error('Final route cannot become bootstrap');await this.codec.localOffer(data.localBundle,owner);const certificate=JSON.parse(data.localBundle).inbound_certificate;
    if(!Array.isArray(data.recipientKeys)||data.recipientKeys.length!==1||material.some(v=>!(v instanceof Uint8Array)||v.length!==32))throw Error('Bootstrap private material required');
    sign=nacl.sign.keyPair.fromSeed(data.discoverySeed);box=nacl.box.keyPair.fromSecretKey(data.discoveryBox);
    if(hex(sign.publicKey)!==certificate.discovery_sign||hex(box.publicKey)!==certificate.discovery_box)throw Error('Bootstrap discovery authority mismatch');
    this.local.validateRecipient({certificate},data.recipientKeys);
    await this.dispatcher.register(token,data.localBundle);
    const key=await this.dispatcher.key('config',owner),old=await this.dispatcher.load(key),saved={...old.value,owner:{...owner},certificate,discoverySeed:hex(data.discoverySeed),discoveryBox:hex(data.discoveryBox),recipientKeys:data.recipientKeys.map(hex),suspended:false};
    if(old.value.discoverySeed){if(old.value.discoverySeed!==saved.discoverySeed||old.value.discoveryBox!==saved.discoveryBox||old.value.recipientKeys[0]!==saved.recipientKeys[0])throw Error('Bootstrap material changed');if(old.value.suspended)throw Error('Bootstrap already retired');}
    else await this.dispatcher.save(token,key,old,saved);
    this.ownership.owner(token);await this.attach(saved);return {provisioned:true,state:'BOOTSTRAP_ONLY'};
   }finally{sign?.secretKey.fill(0);box?.secretKey.fill(0);for(const value of material)value?.fill?.(0);}
  }
  async attach(config){
   this.check();if(this.#routes.has(config.owner.routeId))return;
   if(config.suspended||JSON.parse(config.localBundle).expires_at<=Math.floor(Date.now()/1000))return;
   const final=await this.ownership.read(config.owner.routeId);if(final?.state==='ACTIVE'){await this.suspendFinal(config.owner,final);return;}if(final?.state==='RETIRED')return;
   await this.codec.localOffer(config.localBundle,config.owner);
   if(await this.ownership.inbox.alias('local-account-owner-v4|'+config.owner.accountPublic)!==config.owner.ownerSlot)throw Error('Bootstrap blind owner mismatch');
   const rootToken=Object.freeze({}),seed=decode(config.discoverySeed),boxSeed=decode(config.discoveryBox),keys=config.recipientKeys.map(decode),sign=nacl.sign.keyPair.fromSeed(seed),box=nacl.box.keyPair.fromSecretKey(boxSeed);seed.fill(0);boxSeed.fill(0);
   let installed=false;
   try{
    const entry={owner:config.owner,rootToken,sign,box,keys,handler:null};
    entry.handler=async(_,packet)=>{this.check();const opened=g.DmashRecipientPayloadV4.openPayload(keys,packet.payload);if(opened.status!=='accepted')return {discarded:true};let value;try{value=JSON.parse(opened.payload);}catch(_){return {discarded:true};}
     try{if(value.type==='NODE_BOOTSTRAP_REQUEST_V4')return await this.dispatcher.request(rootToken,opened.payload);
     if(value.type==='NODE_BOOTSTRAP_RECEIPT_V4'&&Object.keys(value).sort().join(',')==='exchange_id,receipt,type')return await this.dispatcher.receipt(rootToken,value.exchange_id,value.receipt);
     return {discarded:true};}catch(_){this.check();return {discarded:true};}};
    this.#roots.set(rootToken,config.owner);this.runtime.bindLocal(config.certificate,sign,box,entry.handler);this.#routes.set(config.owner.routeId,entry);installed=true;
   }finally{if(!installed){this.#roots.delete(rootToken);sign.secretKey.fill(0);box.secretKey.fill(0);for(const k of keys)k.fill(0);}}
  }
  async archiveRow(owner){this.check();const key=await this.dispatcher.key('config',owner),row=await this.dispatcher.load(key);if(!row?.value.owner||!row.value.certificate)return null;return {ownership:row.value.owner,certificate:row.value.certificate};}
  async restore(){let unavailable=0;for(const row of await this.inbox.store.all()){try{const value=await this.inbox.decrypt(row);if(value.kind==='bootstrap-config'&&value.owner&&value.discoverySeed)await this.attach(value);}catch(_){this.check();unavailable++;}}return {restored:this.#routes.size,unavailable};}
  async suspendFinal(owner,final){
   this.check();this.ownership.matches(final,owner);if(final.state!=='ACTIVE')throw Error('Bootstrap final state required');
   const key=await this.dispatcher.key('config',owner);
   for(let attempt=0;attempt<8;attempt++){const old=await this.dispatcher.load(key);if(!old||old.value.suspended)return;
    const epoch=Number.isSafeInteger(final.activatedAt)&&final.activatedAt>0&&final.activatedAt<=Math.floor(Date.now()/1000)?final.activatedAt:null;
    const value={...old.value,suspended:true,continuationUntil:epoch===null?0:Math.min(JSON.parse(old.value.localBundle).expires_at,epoch+300),continuationSent:0,continuationReceived:0};
    const encrypted=await this.inbox.encrypt(key,value);this.check();const current=await this.ownership.read(owner.routeId);this.ownership.matches(current,owner);if(current.state!=='ACTIVE'||current.activatedAt!==final.activatedAt)throw Error('Bootstrap final state changed');
    if(await this.inbox.store.cas(key,old.row.revision,encrypted))return;
   }throw Error('Bootstrap retirement conflict');
  }
  async detach(routeId){
   const entry=this.#routes.get(routeId),final=await this.ownership.read(routeId);if(final?.state==='ACTIVE')await this.suspendFinal(entry?.owner||final.ownership,final);if(!entry)return;
   this.runtime.owned=this.runtime.owned.filter(row=>row.handler!==entry.handler);for(const [key,row]of this.runtime.labels)if(row.target===entry.handler)this.runtime.labels.delete(key);
   this.#roots.delete(entry.rootToken);this.#routes.delete(routeId);entry.sign.secretKey.fill(0);entry.box.secretKey.fill(0);for(const key of entry.keys)key.fill(0);
  }
  async spendContinuation(token,owner,field){
   this.check();const final=await this.ownership.read(owner.routeId);if(!final||final.state!=='ACTIVE')throw Error('Final receipt owner unavailable');this.ownership.matches(final,owner);
   const key=await this.dispatcher.key('config',owner),old=await this.dispatcher.load(key);if(!old||!old.value.suspended||!Number.isSafeInteger(old.value.continuationUntil)||old.value.continuationUntil<=Math.floor(Date.now()/1000)||!Number.isSafeInteger(old.value[field])||old.value[field]>=16)throw Error('Final receipt continuation expired or exhausted');
   await this.dispatcher.save(token,key,old,{...old.value,[field]:old.value[field]+1});this.check();const fresh=await this.ownership.read(owner.routeId);if(!fresh||fresh.state!=='ACTIVE')throw Error('Final receipt owner retired');this.ownership.matches(fresh,owner);
  }
  async receiveFinal(routeId,packet,keys){
   this.check();const opened=g.DmashRecipientPayloadV4.openPayload(keys,packet.payload);if(opened.status!=='accepted')return false;let value;try{value=JSON.parse(opened.payload);}catch(_){return false;}
   if(!['NODE_BOOTSTRAP_REQUEST_V4','NODE_BOOTSTRAP_RECEIPT_V4'].includes(value?.type))return false;
   // This namespace never becomes an application message on a final route.
   if(value.type!=='NODE_BOOTSTRAP_RECEIPT_V4'||Object.keys(value).sort().join(',')!=='exchange_id,receipt,type')return true;
   const final=await this.ownership.read(routeId);if(!final||final.state!=='ACTIVE')return true;const owner=final.ownership,token=Object.freeze({});this.#roots.set(token,owner);
   try{const records=await this.dispatcher.list(token),record=records.find(r=>r.exchangeId===value.exchange_id&&r.state==='SELECTED');if(!record||!Object.values(record.receipts).includes(value.receipt))return true;await this.dispatcher.receipt(token,value.exchange_id,value.receipt);await this.spendContinuation(token,owner,'continuationReceived');return true;}
   catch(_){this.check();return true;}finally{this.#roots.delete(token);}
  }
  async submit(token,handle,data){
   const owner=this.ownership.owner(token),provisional=this.#routes.get(owner.routeId),entry=provisional||this.local.bindings.get(owner.routeId),destination=this.local.routes.get(handle);if(!entry||!destination)throw Error('Bootstrap route unavailable');if(destination.ownerToken!==token)throw Error('Bootstrap destination owner mismatch');let wire;
   if(data.kind==='REQUEST'){
    if(!provisional)throw Error('Final route permits exact receipt continuation only');
    const checked=await this.codec.inspect(data.targetBundle,data.serialized);if(checked.remoteAccount!==owner.accountPublic)throw Error('Outbound bootstrap signer mismatch');
    const target=JSON.parse(data.targetBundle).inbound_certificate;if(g.DmashSecureSession.canonical(target)!==g.DmashSecureSession.canonical(destination.certificate))throw Error('Bootstrap destination mismatch');
    await this.dispatcher.request(token,data.serialized,{targetBundle:data.targetBundle,outbound:true});wire=data.serialized;
   }else if(data.kind==='RECEIPT'){
    const records=await this.dispatcher.list(token),record=records.find(v=>v.exchangeId===data.exchangeId);if(!record||record.state!=='SELECTED')throw Error('Bootstrap selection required');
    const peerBundle=record.direction==='OUTBOUND'?record.targetBundle:JSON.parse(record.serialized).bundle;
    if(g.DmashSecureSession.canonical(JSON.parse(peerBundle).inbound_certificate)!==g.DmashSecureSession.canonical(destination.certificate))throw Error('Bootstrap receipt destination mismatch');
    if(!provisional){if(!Object.values(record.receipts).includes(data.serialized))throw Error('Final receipt substitution');await this.spendContinuation(token,owner,'continuationSent');}
    await this.dispatcher.receipt(token,data.exchangeId,data.serialized);wire=g.DmashSecureSession.canonical({type:'NODE_BOOTSTRAP_RECEIPT_V4',exchange_id:data.exchangeId,receipt:data.serialized});this.codec.fits(wire);
   }else throw Error('Bootstrap user payload forbidden');
   this.ownership.owner(token);this.check();if(this.local.routes.get(handle)!==destination||destination.ownerToken!==token)throw Error('Bootstrap destination released');this.runtime.send(destination.route,g.DmashRecipientPayloadV4.sealPayload(decode(destination.certificate.recipient_box),wire),entry.handler);return {queued:true};
  }
  close(){if(this.closed)return;this.closed=true;for(const entry of this.#routes.values()){entry.sign.secretKey.fill(0);entry.box.secretKey.fill(0);for(const key of entry.keys)key.fill(0);}this.#routes.clear();this.#roots.clear();this.dispatcher?.close();}
 }
 g.DmashNodeBootstrapRuntimeV4=BootstrapRuntime;if(typeof module!=='undefined')module.exports=BootstrapRuntime;
})(globalThis);

'use strict';
// Local public-contact controls. Never invoked on transit ciphertext.
(function(g){
 const text=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 const canonical=v=>g.DmashSecureSession.canonical(v);
 const unhex=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Public control encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const hash=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(v))));
 const exact=(v,keys)=>{if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==keys.split(',').sort().join(','))throw Error('Public control schema');};
 const profiles=Object.freeze(['NODE_TRANSPORT_V4','DMASH_PAIRING_V2']);
 function fits(wire){if(typeof wire!=='string')throw Error('Public control required');const expanded=JSON.stringify({type:'RECIPIENT_PAYLOAD',version:2,packet_id:'0'.repeat(64),payload:wire});if(text(expanded).length+72>16384)throw Error('Public control envelope too large');return wire;}
 function createCodec({pairing,binding,discovery=g.DmashRouteDiscoveryV4,clock=()=>Math.floor(Date.now()/1000)}){
  const requests=new WeakMap(),accepts=new WeakMap(),confirms=new WeakMap();
  function parse(wire,fields,type){fits(wire);const value=JSON.parse(wire);exact(value,fields);if(canonical(value)!==wire||value.type!==type||value.version!==2)throw Error('Public control canonical profile');return value;}
  function dates(value,ceiling){const now=clock();if(!Number.isSafeInteger(value.issued_at)||!Number.isSafeInteger(value.expires_at)||value.issued_at<0||value.issued_at>now+60||value.expires_at<=now||value.expires_at<=value.issued_at||value.expires_at-value.issued_at>86400||value.expires_at>ceiling)throw Error('Public control expiry');}
  const transcript=(kind,body)=>text('D-MASH|PUBLIC-CONTACT|'+kind+'|V2\0'+canonical(body));
  function verify(kind,value,signer){discovery.validateEd25519PublicEncoding(signer);discovery.validateEd25519SignatureEncoding(value.signature);const {signature,...body}=value;if(!g.nacl.sign.detached.verify(transcript(kind,body),Uint8Array.from(signature.match(/../g),x=>parseInt(x,16)),unhex(signer)))throw Error('Public control signature');}
  function sign(kind,body,secret,expected){const keys=g.nacl.sign.keyPair.fromSecretKey(secret);try{if(hex(keys.publicKey)!==expected)throw Error('Public control signer mismatch');return fits(canonical({...body,signature:hex(g.nacl.sign.detached(transcript(kind,body),secret))}));}finally{keys.secretKey.fill(0);}}
  async function inspectRequest(targetCertificate,wire){
   discovery.verifyCertificate(targetCertificate,clock());const value=parse(wire,'type,version,request_id,target_digest,issued_at,expires_at,display_name,introduction,reply_certificate,bootstrap_box,profiles,nonce,signature','CONTACT_REQUEST_V2');
   unhex(value.request_id);unhex(value.nonce);unhex(value.target_digest);discovery.verifyCertificate(value.reply_certificate,clock());discovery.validateX25519PublicKey(value.bootstrap_box);
   if(value.target_digest!==await hash(canonical(targetCertificate))||canonical(value.profiles)!==canonical(profiles))throw Error('Public target/profile mismatch');
   if(typeof value.display_name!=='string'||!text(value.display_name).length||text(value.display_name).length>128||typeof value.introduction!=='string'||text(value.introduction).length>4096)throw Error('Public introduction size');
   dates(value,Math.min(targetCertificate.expires_at,value.reply_certificate.expires_at));verify('REQUEST',value,value.reply_certificate.route_id);
   const handle=Object.freeze({requestId:value.request_id,digest:await hash(wire),expiresAt:value.expires_at,displayName:value.display_name,introduction:value.introduction,identityStatus:'ACCOUNT_NEUTRAL'});requests.set(handle,{value,wire,targetCertificate});return handle;
  }
  async function request(targetCertificate,{requestId,replyCertificate,bootstrapBox,displayName,introduction,nonce,expiresAt},routeSecret){
   const body={type:'CONTACT_REQUEST_V2',version:2,request_id:requestId,target_digest:await hash(canonical(targetCertificate)),issued_at:clock(),expires_at:expiresAt??Math.min(clock()+86400,targetCertificate.expires_at,replyCertificate.expires_at),display_name:displayName,introduction,reply_certificate:replyCertificate,bootstrap_box:bootstrapBox,profiles:[...profiles],nonce};
   const wire=sign('REQUEST',body,routeSecret,replyCertificate.route_id);await inspectRequest(targetCertificate,wire);return wire;
  }
  async function inspectAccept(requestHandle,wire){
   const request=requests.get(requestHandle);if(!request||requestHandle.expiresAt<=clock())throw Error('Public request capability expired');
   const value=parse(wire,'type,version,request_digest,request_id,bundle,bootstrap_box,issued_at,expires_at,signature','CONTACT_ACCEPT_V2');
   if(value.request_digest!==requestHandle.digest||value.request_id!==requestHandle.requestId)throw Error('Public accept context');
   discovery.validateX25519PublicKey(value.bootstrap_box);const offer=pairing.parse(value.bundle,{now:clock()});
   if([offer.bundle.account_keys.box,offer.bundle.inbound_certificate.discovery_box,offer.bundle.inbound_certificate.recipient_box].includes(value.bootstrap_box))throw Error('Fresh public bootstrap box required');
   if(offer.bundle.intended_peer!==null||offer.bundle.generation!==1)throw Error('Public accept must be fresh neutral offer');
   dates(value,Math.min(requestHandle.expiresAt,offer.bundle.expires_at));verify('ACCEPT',value,offer.bundle.account_keys.signing);
   const handle=Object.freeze({requestId:requestHandle.requestId,requestDigest:requestHandle.digest,digest:await hash(wire),accountPublic:offer.bundle.account_keys.signing,expiresAt:value.expires_at,identityStatus:'UNSELECTED_CANDIDATE'});accepts.set(handle,{requestHandle,request,value,wire,offer});return handle;
  }
  async function accept(requestHandle,{bundle,bootstrapBox,expiresAt},accountSecret){
   const request=requests.get(requestHandle);if(!request)throw Error('Public request capability required');const offer=pairing.parse(bundle,{now:clock()});
   const body={type:'CONTACT_ACCEPT_V2',version:2,request_digest:requestHandle.digest,request_id:requestHandle.requestId,bundle,bootstrap_box:bootstrapBox,issued_at:clock(),expires_at:expiresAt??Math.min(requestHandle.expiresAt,offer.bundle.expires_at)};
   const wire=sign('ACCEPT',body,accountSecret,offer.bundle.account_keys.signing);await inspectAccept(requestHandle,wire);return wire;
  }
  async function inspectConfirm(acceptHandle,wire){
   const accepted=accepts.get(acceptHandle);if(!accepted||acceptHandle.expiresAt<=clock())throw Error('Public accept capability expired');
   const value=parse(wire,'type,version,request_digest,accept_digest,bundle,accept_receipt,issued_at,expires_at,signature','CONTACT_CONFIRM_V2');
   if(value.request_digest!==acceptHandle.requestDigest||value.accept_digest!==acceptHandle.digest)throw Error('Public confirm context');
   const offer=pairing.parse(value.bundle,{now:clock(),localAccount:acceptHandle.accountPublic});
   if(offer.bundle.intended_peer!==acceptHandle.accountPublic||offer.bundle.generation!==1)throw Error('Public confirm targeted offer required');
   dates(value,Math.min(acceptHandle.expiresAt,offer.bundle.expires_at));const remote=offer.bundle.account_keys.signing;verify('CONFIRM',value,remote);
   const candidate=await binding.prepare([accepted.value.bundle,value.bundle],{expectedParticipants:[acceptHandle.accountPublic,remote],committed:null});
   if(remote<acceptHandle.accountPublic){if(value.accept_receipt===null)throw Error('Public lower requester needs reserved ACCEPT');binding.verifyReceipt(candidate,value.accept_receipt,'ACCEPT');}else if(value.accept_receipt!==null)throw Error('Public premature binding receipt');
   const handle=Object.freeze({requestId:acceptHandle.requestId,digest:await hash(wire),bindingDigest:candidate.digest,expiresAt:value.expires_at,localAccount:acceptHandle.accountPublic,remoteAccount:remote});confirms.set(handle,{accepted,value,wire,candidate});return handle;
  }
  async function confirm(acceptHandle,{bundle,acceptReceipt=null,expiresAt},accountSecret){
   const accepted=accepts.get(acceptHandle);if(!accepted)throw Error('Public accept capability required');const offer=pairing.parse(bundle,{now:clock(),localAccount:acceptHandle.accountPublic});
   const body={type:'CONTACT_CONFIRM_V2',version:2,request_digest:acceptHandle.requestDigest,accept_digest:acceptHandle.digest,bundle,accept_receipt:acceptReceipt,issued_at:clock(),expires_at:expiresAt??Math.min(acceptHandle.expiresAt,offer.bundle.expires_at)};
   const wire=sign('CONFIRM',body,accountSecret,offer.bundle.account_keys.signing);await inspectConfirm(acceptHandle,wire);return wire;
  }
  function receipt(confirmHandle,wire,phase){const state=confirms.get(confirmHandle);if(!state||confirmHandle.expiresAt<=clock())throw Error('Public confirmed context expired');if(typeof wire!=='string'||text(wire).length>2048)throw Error('Public receipt size');return Object.freeze({...binding.verifyReceipt(state.candidate,wire,phase)});}
  return Object.freeze({request,inspectRequest,accept,inspectAccept,confirm,inspectConfirm,receipt,fits});
 }
 g.DmashNodePublicBootstrapControlV4=Object.freeze({createCodec,fits,profiles});if(typeof module!=='undefined')module.exports=g.DmashNodePublicBootstrapControlV4;
})(globalThis);

'use strict';
// Root-owned public/reply registrations and neutral control journal. Account
// secrets never enter this actor. Final ownership activation is a separate API.
(function(g){
 const text=s=>new TextEncoder().encode(s),hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),canonical=v=>g.DmashSecureSession.canonical(v);
 const decode=s=>{if(typeof s!=='string'||!/^[0-9a-f]{64}$/.test(s))throw Error('Public material encoding');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));};
 const hash=async s=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',text(s))));
 class PublicRuntime{
  #caps=new Map();#routes=new Map();#replays=new Set();#tail=Promise.resolve();
  static async open(storageKey,nodeId,{runtime,ownership,local,isCurrent}){
   const base=await crypto.subtle.importKey('raw',storageKey,{name:'HMAC',hash:'SHA-256'},false,['sign']),key=new Uint8Array(await crypto.subtle.sign('HMAC',base,text('D-MASH|NODE-PUBLIC-BOOTSTRAP|V4|STORAGE')));
   let inbox;try{inbox=await g.DmashNodeInboxV4.open(key,nodeId,{databaseName:'dmash_node_public_bootstrap_v4',maxRecords:128,maxBytes:1536*1024,isCurrent});}finally{key.fill(0);}
   const result=new PublicRuntime();Object.assign(result,{runtime,ownership,local,inbox,isCurrent,closed:false});
   const pairing=g.DmashAccountPairingV2.createCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4}),binding=g.DmashAccountRouteBindingV2.createBindingCodec({nacl:g.nacl,discovery:g.DmashRouteDiscoveryV4,pairing});
   result.codec=g.DmashNodePublicBootstrapControlV4.createCodec({pairing,binding});result.privateCodec=g.DmashNodeBootstrapControlV4.createCodec({pairing,binding});
   try{await result.restore();return result;}catch(error){result.close();throw error;}
  }
  check(){if(this.closed||!this.isCurrent())throw Error('Public root closed');this.inbox.check();}
  run(fn){const task=this.#tail.then(()=>{this.check();return fn();});this.#tail=task.catch(()=>{});return task;}
  async key(kind,id,request=''){return this.inbox.alias('public-v4|'+kind+'|'+id+'|'+request);}
  async load(key){const row=await this.inbox.store.read(key);this.check();return row?{row,value:await this.inbox.decrypt(row)}:null;}
  async save(key,old,value,guard=()=>true){if(value.kind==='public-request'){let bytes=text(canonical(value)).length;for(const row of await this.rows('public-request'))if(row.row.key!==key)bytes+=text(canonical(row.value)).length;if(bytes>1024*1024)throw Error('Public total control bytes quota');}const encrypted=await this.inbox.encrypt(key,value);this.check();guard();if(!await this.inbox.store.cas(key,old?.row.revision??null,encrypted,{guard:()=>{this.check();return guard();}}))throw Error('Public journal conflict');}
  async rows(kind){const values=[];for(const row of await this.inbox.store.all()){try{const value=await this.inbox.decrypt(row);if(value.kind===kind)values.push({row,value});}catch(_){this.check();}}return values;}
  capability(token){this.check();const value=this.#caps.get(token);if(!value)throw Error('Public root capability unavailable');return value;}
  descriptor(config){return {id:config.id,kind:config.routeKind,certificate:config.certificate,bootstrapBox:config.bootstrapBox,profile:'public-v1',installed:this.#routes.has(config.id)};}
  routes(){return this.run(async()=>{const rows=await this.rows('public-config');return rows.map(row=>this.descriptor(row.value));});}
  register(data){return this.run(async()=>{
   let config;if(data.id){decode(data.id);const saved=await this.load(await this.key('config',data.id));if(!saved||saved.value.kind!=='public-config')throw Error('Public registration absent');config=saved.value;}
   else{
    if(!['PUBLIC_INTAKE','PUBLIC_REPLY'].includes(data.kind))throw Error('Public route kind');const now=Math.floor(Date.now()/1000),max=data.kind==='PUBLIC_REPLY'?86400:30*86400;
    if(!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=now||data.expiresAt>now+max)throw Error('Public registration expiry');
    if((await this.rows('public-config')).length>=16)throw Error('Public registration quota');
    const route=g.nacl.sign.keyPair(),sign=g.nacl.sign.keyPair(),box=g.nacl.box.keyPair(),recipient=g.nacl.box.keyPair(),bootstrap=g.nacl.box.keyPair();
    try{config={kind:'public-config',id:hex(crypto.getRandomValues(new Uint8Array(32))),routeKind:data.kind,certificate:g.DmashRouteDiscoveryV4.issueCertificate(route,sign.publicKey,box.publicKey,recipient.publicKey,{generation:1,issuedAt:now,expiresAt:data.expiresAt}),routeSeed:hex(route.secretKey.subarray(0,32)),discoverySeed:hex(sign.secretKey.subarray(0,32)),discoveryBox:hex(box.secretKey),recipientKey:hex(recipient.secretKey),bootstrapKey:hex(bootstrap.secretKey),bootstrapBox:hex(bootstrap.publicKey)};await this.save(await this.key('config',config.id),null,config);}finally{for(const k of [route.secretKey,sign.secretKey,box.secretKey,recipient.secretKey,bootstrap.secretKey])k.fill(0);}
   }
   if(this.#caps.size>=32)throw Error('Public handle quota');await this.attach(config);const token=hex(crypto.getRandomValues(new Uint8Array(32)));this.#caps.set(token,config);return {token,...this.descriptor(config)};
  });}
  release(token){this.#caps.delete(token);return {released:true};}
  async attach(config){
   this.check();if(this.#routes.has(config.id)||config.certificate.expires_at<=Math.floor(Date.now()/1000))return;
   g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);const seed=decode(config.discoverySeed),boxSeed=decode(config.discoveryBox),sign=g.nacl.sign.keyPair.fromSeed(seed),box=g.nacl.box.keyPair.fromSecretKey(boxSeed),recipient=decode(config.recipientKey),recipientPair=g.nacl.box.keyPair.fromSecretKey(recipient);seed.fill(0);boxSeed.fill(0);const recipientPublic=hex(recipientPair.publicKey);recipientPair.secretKey.fill(0);
   if(hex(sign.publicKey)!==config.certificate.discovery_sign||hex(box.publicKey)!==config.certificate.discovery_box||recipientPublic!==config.certificate.recipient_box){sign.secretKey.fill(0);box.secretKey.fill(0);recipient.fill(0);throw Error('Public stored material mismatch');}
   const handler=async(_,packet)=>{try{this.check();const opened=g.DmashRecipientPayloadV4.openPayload([recipient],packet.payload);if(opened.status!=='accepted')return {discarded:true};return await this.run(()=>this.receive(config,opened.payload));}catch(_){this.check();return {discarded:true};}};
   try{this.runtime.bindLocal(config.certificate,sign,box,handler);this.#routes.set(config.id,{config,sign,box,recipient,handler});}catch(error){sign.secretKey.fill(0);box.secretKey.fill(0);recipient.fill(0);throw error;}
  }
  async restore(){for(const row of await this.rows('public-config')){try{await this.attach(row.value);}catch(_){this.check();}}}
  async quota(config,wire){let bytes=0,count=0,local=0;for(const row of await this.rows('public-request')){if(row.value.expiresAt<=Math.floor(Date.now()/1000)&&['PENDING','DENIED','REQUESTED'].includes(row.value.state)){await this.inbox.store.cas(row.row.key,row.row.revision,null,{guard:()=>{this.check();return true;}});continue;}count++;if(row.value.registration===config.id)local++;bytes+=text(canonical(row.value)).length;}if(count>=64||local>=16||bytes+text(wire).length>1024*1024)throw Error('Public request quota');}
  async receive(config,wire){
   const value=JSON.parse(wire);if(value.type==='CONTACT_PRIVATE_V2')return this.receivePrivate(config,value);if(value.type!=='CONTACT_REQUEST_V2'||config.routeKind!=='PUBLIC_INTAKE')throw Error('Public control unavailable');
   const checked=await this.codec.inspectRequest(config.certificate,wire),key=await this.key('request',config.id,checked.requestId),old=await this.load(key);
   if(old){if(old.value.requestDigest!==checked.digest)throw Error('Conflicting public replay');return {stored:true,duplicate:true};}
   await this.quota(config,wire);await this.save(key,null,{kind:'public-request',registration:config.id,requestId:checked.requestId,requestDigest:checked.digest,expiresAt:checked.expiresAt,state:'PENDING',direction:'INBOUND',request:wire,claim:null});return {stored:true,duplicate:false};
  }
  list(token,{limit=16,after=null}={}){return this.run(async()=>{if(!Number.isInteger(limit)||limit<1||limit>16)throw Error('Public page limit');if(after!==null)decode(after);const config=this.capability(token),rows=await this.rows('public-request');this.capability(token);return rows.filter(row=>row.value.registration===config.id&&(after===null||row.value.requestId>after)).sort((a,b)=>a.value.requestId.localeCompare(b.value.requestId)).slice(0,limit).map(({value})=>{const {blob,acceptBlob,confirmBlob,receiptBlobs,claim,...projection}=value;const safeClaim=claim?(({bootstrapKey,...publicClaim})=>publicClaim)(claim):null;return {...projection,claim:safeClaim,state:value.expiresAt<=Math.floor(Date.now()/1000)?'EXPIRED_'+value.state:value.state};});});}
  request(token,targetCertificate,data){return this.run(async()=>{
   const config=this.capability(token);if(config.routeKind!=='PUBLIC_REPLY')throw Error('Reply registration required');g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);
   decode(data.requestId);const prior=await this.load(await this.key('request',config.id,data.requestId));let wire;
   if(prior){const original=JSON.parse(prior.value.request);if(original.display_name!==data.displayName||original.introduction!==data.introduction||original.nonce!==data.nonce||(data.expiresAt!==undefined&&original.expires_at!==data.expiresAt)||canonical(prior.value.targetCertificate)!==canonical(targetCertificate))throw Error('Public outbound retry context changed');wire=prior.value.request;}
   else{const seed=decode(config.routeSeed),sign=g.nacl.sign.keyPair.fromSeed(seed);seed.fill(0);try{wire=await this.codec.request(targetCertificate,{...data,replyCertificate:config.certificate,bootstrapBox:config.bootstrapBox},sign.secretKey);}finally{sign.secretKey.fill(0);}}
   const checked=await this.codec.inspectRequest(targetCertificate,wire),key=await this.key('request',config.id,checked.requestId),old=await this.load(key);let saved;
   if(old){if(old.value.requestDigest!==checked.digest)throw Error('Public outbound retry changed bytes');saved=old.value;}
   else{await this.quota(config,wire);saved={kind:'public-request',registration:config.id,requestId:checked.requestId,requestDigest:checked.digest,expiresAt:checked.expiresAt,state:'REQUESTED',direction:'OUTBOUND',request:wire,targetCertificate,blob:g.DmashRecipientPayloadV4.sealPayload(decode(targetCertificate.recipient_box),wire),claim:null};await this.save(key,null,saved,()=>{this.capability(token);return true;});}
   this.capability(token);const found=await this.local.discover(targetCertificate);this.capability(token);g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);g.DmashRouteDiscoveryV4.verifyCertificate(targetCertificate);if(saved.expiresAt<=Math.floor(Date.now()/1000))throw Error('Public request expired before send');const route=this.local.routes.get(found.handle),entry=this.#routes.get(config.id);if(!route||!entry)throw Error('Public reply route unavailable');this.runtime.send(route.route,saved.blob,entry.handler);return {queued:true,requestId:checked.requestId,requestDigest:checked.digest};
  });}
  decline(token,requestId,requestDigest){return this.run(async()=>{const config=this.capability(token),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.direction!=='INBOUND'||!['PENDING','DENIED'].includes(old.value.state))throw Error('Public decline context');if(old.value.state==='DENIED')return {denied:true};await this.save(key,old,{...old.value,state:'DENIED',request:null},()=>{this.capability(token);return true;});return {denied:true};});}
  claim(token,ownerToken,requestId,requestDigest,localBundle){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken);if(config.routeKind!=='PUBLIC_INTAKE')throw Error('Public intake required');const final=await this.ownership.read(owner.routeId);this.ownership.owner(ownerToken);if(final&&['ACTIVE','RETIRED'].includes(final.state))throw Error('Public claim cannot reuse final route');await this.privateCodec.localOffer(localBundle,owner);if(JSON.parse(localBundle).intended_peer!==null)throw Error('Public claim requires neutral offer');
   const key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.requestDigest!==requestDigest||old.value.expiresAt<=Math.floor(Date.now()/1000)||!['PENDING','CLAIMED'].includes(old.value.state))throw Error('Public claim context');
   if(old.value.claim){if(old.value.claim.ownerSlot!==owner.ownerSlot||old.value.claim.routeAuthorityDigest!==owner.routeAuthorityDigest||old.value.claim.localBundle!==localBundle)throw Error('Public request already claimed');return {claimed:true,bootstrapBox:old.value.claim.bootstrapBox};}
   const box=g.nacl.box.keyPair();try{const claim={ownerSlot:owner.ownerSlot,routeAuthorityDigest:owner.routeAuthorityDigest,accountPublic:owner.accountPublic,localBundle,bootstrapBox:hex(box.publicKey),bootstrapKey:hex(box.secretKey)};await this.save(key,old,{...old.value,state:'CLAIMED',claim},()=>{this.capability(token);this.ownership.owner(ownerToken);return true;});return {claimed:true,bootstrapBox:claim.bootstrapBox};}finally{box.secretKey.fill(0);}
  });}
  async contexts(config,row){const target=row.direction==='INBOUND'?config.certificate:row.targetCertificate,request=await this.codec.inspectRequest(target,row.request),accepted=row.accept?await this.codec.inspectAccept(request,row.accept):null,confirmed=row.confirm?await this.codec.inspectConfirm(accepted,row.confirm):null;return {request,accepted,confirmed};}
  envelope(requestId,kind,wire,key){const box=g.DmashRouteDiscoveryV4.seal(decode(key),{wire});return this.codec.fits(canonical({type:'CONTACT_PRIVATE_V2',request_id:requestId,kind,box}));}
  sealed(certificate,wire){return g.DmashRecipientPayloadV4.sealPayload(decode(certificate.recipient_box),wire);}
  async sendStored(config,certificate,blob,guard,expiresAt){guard();const found=await this.local.discover(certificate);guard();g.DmashRouteDiscoveryV4.verifyCertificate(config.certificate);g.DmashRouteDiscoveryV4.verifyCertificate(certificate);if(!Number.isSafeInteger(expiresAt)||expiresAt<=Math.floor(Date.now()/1000))throw Error('Public control expired before send');const destination=this.local.routes.get(found.handle),entry=this.#routes.get(config.id);if(!destination||!entry)throw Error('Public sender registration unavailable');this.runtime.send(destination.route,blob,entry.handler);return {queued:true};}
  checkClaim(row,owner){if(!row.claim||row.claim.ownerSlot!==owner.ownerSlot||row.claim.routeAuthorityDigest!==owner.routeAuthorityDigest||row.claim.accountPublic!==owner.accountPublic)throw Error('Public claim owner mismatch');}
  accept(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.direction!=='INBOUND')throw Error('Public inbound request required');this.checkClaim(old.value,owner);
   const context=await this.contexts(config,old.value),checked=await this.codec.inspectAccept(context.request,wire),value=JSON.parse(wire);if(checked.accountPublic!==owner.accountPublic||value.bundle!==old.value.claim.localBundle||value.bootstrap_box!==old.value.claim.bootstrapBox)throw Error('Public accept claim mismatch');
   const request=JSON.parse(old.value.request);let saved=old.value;if(saved.accept&&saved.accept!==wire)throw Error('Public accept replay changed');const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;};
   if(!saved.accept){const wrapped=this.envelope(requestId,'ACCEPT',wire,request.bootstrap_box);saved={...saved,state:'ACCEPTED',accept:wire,acceptBlob:this.sealed(request.reply_certificate,wrapped)};await this.save(key,old,saved,guard);}
   return this.sendStored(config,request.reply_certificate,saved.acceptBlob,guard,value.expires_at);
  });}
  confirm(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old||old.value.direction!=='OUTBOUND'||!old.value.accept)throw Error('Public accepted candidate required');
   const context=await this.contexts(config,old.value),checked=await this.codec.inspectConfirm(context.accepted,wire),value=JSON.parse(wire);if(checked.remoteAccount!==owner.accountPublic)throw Error('Public confirming Account mismatch');await this.privateCodec.localOffer(value.bundle,owner);const final=await this.ownership.read(owner.routeId);this.ownership.owner(ownerToken);if(final&&['ACTIVE','RETIRED'].includes(final.state)&&!old.value.confirm)throw Error('Public confirm cannot reuse final route');
   const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;};let saved=old.value;
   if(saved.confirm){this.checkClaim(saved,owner);if(saved.confirm!==wire)throw Error('Public confirm replay changed');}
   else{const wrapped=this.envelope(requestId,'CONFIRM',wire,JSON.parse(saved.accept).bootstrap_box);saved={...saved,state:'CONFIRMED',confirm:wire,confirmBlob:this.sealed(saved.targetCertificate,wrapped),receipts:value.accept_receipt?{ACCEPT:value.accept_receipt}:{},claim:{ownerSlot:owner.ownerSlot,routeAuthorityDigest:owner.routeAuthorityDigest,accountPublic:owner.accountPublic,localBundle:value.bundle}};await this.save(key,old,saved,guard);}
   return this.sendStored(config,saved.targetCertificate,saved.confirmBlob,guard,value.expires_at);
  });}
  replaySaved(key,config,certificate,blob,expiresAt){if(this.#replays.has(key)||this.#replays.size>=16)return;this.#replays.add(key);setTimeout(()=>{this.sendStored(config,certificate,blob,()=>{this.check();return true;},expiresAt).catch(()=>{}).finally(()=>this.#replays.delete(key));},0);}
  async receivePrivate(config,wrapper){
   if(Object.keys(wrapper).sort().join(',')!=='box,kind,request_id,type'||!['ACCEPT','CONFIRM','RECEIPT'].includes(wrapper.kind))throw Error('Public private wrapper schema');decode(wrapper.request_id);
   const key=await this.key('request',config.id,wrapper.request_id),old=await this.load(key);if(!old||old.value.expiresAt<=Math.floor(Date.now()/1000))throw Error('Public outstanding request required');
   const keyHex=old.value.direction==='OUTBOUND'?config.bootstrapKey:old.value.claim?.bootstrapKey;if(!keyHex)throw Error('Public bootstrap recipient absent');const secret=decode(keyHex);let content;try{content=g.DmashRouteDiscoveryV4.openBox(secret,wrapper.box);}finally{secret.fill(0);}if(!content||Object.keys(content).join(',')!=='wire'||typeof content.wire!=='string')throw Error('Public encrypted content schema');
   const context=await this.contexts(config,old.value);let changes;
   if(wrapper.kind==='ACCEPT'){
    if(old.value.direction!=='OUTBOUND')throw Error('Public accept direction');await this.codec.inspectAccept(context.request,content.wire);if(old.value.accept){if(old.value.accept!==content.wire)throw Error('Public accept conflict');return {stored:true,duplicate:true};}changes={state:'CANDIDATE',accept:content.wire};
   }else if(wrapper.kind==='CONFIRM'){
    if(old.value.direction!=='INBOUND'||!context.accepted)throw Error('Public confirm direction');await this.codec.inspectConfirm(context.accepted,content.wire);if(old.value.confirm){if(old.value.confirm!==content.wire)throw Error('Public confirm conflict');const reply=JSON.parse(old.value.request).reply_certificate;for(const [phase,blob] of Object.entries(old.value.receiptBlobs||{}))this.replaySaved(config.id+'|'+wrapper.request_id+'|'+phase,config,reply,blob,JSON.parse(old.value.confirm).expires_at);return {stored:true,duplicate:true};}const initial=JSON.parse(content.wire).accept_receipt;changes={state:'CONFIRMED',confirm:content.wire,receipts:initial?{ACCEPT:initial}:{}};
   }else{
    if(!context.confirmed)throw Error('Public final context absent');const receipt=this.codec.receipt(context.confirmed,content.wire),previous=old.value.receipts?.[receipt.phase];if(previous){if(previous!==content.wire)throw Error('Public receipt conflict');if(receipt.phase==='ACCEPT'&&old.value.direction==='OUTBOUND'&&old.value.receiptBlobs?.CONFIRM)this.replaySaved(config.id+'|'+wrapper.request_id+'|CONFIRM',config,old.value.targetCertificate,old.value.receiptBlobs.CONFIRM,JSON.parse(old.value.confirm).expires_at);return {stored:true,duplicate:true};}if(receipt.phase==='CONFIRM'&&!old.value.receipts?.ACCEPT)throw Error('Public ACCEPT receipt required');changes={receipts:{...old.value.receipts,[receipt.phase]:content.wire}};
   }
   await this.save(key,old,{...old.value,...changes});return {stored:true,duplicate:false};
  }
  receipt(token,ownerToken,requestId,wire){return this.run(async()=>{
   const config=this.capability(token),owner=this.ownership.owner(ownerToken),key=await this.key('request',config.id,requestId),old=await this.load(key);if(!old?.value.confirm)throw Error('Public confirmed exchange required');this.checkClaim(old.value,owner);const context=await this.contexts(config,old.value),receipt=this.codec.receipt(context.confirmed,wire);if(receipt.signer!==owner.accountPublic)throw Error('Public receipt signer not local owner');
   if(receipt.phase==='CONFIRM'&&!old.value.receipts?.ACCEPT)throw Error('Public ACCEPT receipt required');const previous=old.value.receipts?.[receipt.phase];if(previous&&previous!==wire)throw Error('Public receipt changed');
   const guard=()=>{this.capability(token);this.ownership.owner(ownerToken);return true;},request=JSON.parse(old.value.request),destination=old.value.direction==='INBOUND'?request.reply_certificate:old.value.targetCertificate,box=old.value.direction==='INBOUND'?request.bootstrap_box:JSON.parse(old.value.accept).bootstrap_box;
   let saved=old.value,blob=saved.receiptBlobs?.[receipt.phase];if(!blob){blob=this.sealed(destination,this.envelope(requestId,'RECEIPT',wire,box));saved={...saved,receipts:{...saved.receipts,[receipt.phase]:wire},receiptBlobs:{...saved.receiptBlobs,[receipt.phase]:blob}};await this.save(key,old,saved,guard);}return this.sendStored(config,destination,blob,guard,JSON.parse(saved.confirm).expires_at);
  });}
  close(){if(this.closed)return;this.closed=true;this.#caps.clear();for(const row of this.#routes.values()){row.sign.secretKey.fill(0);row.box.secretKey.fill(0);row.recipient.fill(0);}this.#routes.clear();this.inbox.close();}
 }
 g.DmashNodePublicBootstrapRuntimeV4=PublicRuntime;if(typeof module!=='undefined')module.exports=PublicRuntime;
})(globalThis);

'use strict';
(function(g){
 const fields='can_relay_blob,can_s_turn,challenge,expires_at,holder,issued_at,issuer,signaling_wss,transcript_hash,version',hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x),bytes=x=>Uint8Array.from(x.match(/../g),v=>parseInt(v,16));
 function bodyBytes(b){if(!b||Object.keys(b).sort().join(',')!==fields||b.version!==1)throw Error('SERVICE_SCHEMA');for(const k of ['issuer','holder','challenge','transcript_hash'])if(!hex(b[k]))throw Error('SERVICE_CONTEXT');for(const k of ['issuer','holder'])g.DmashRouteDiscoveryV4.validateEd25519PublicEncoding(b[k]);if(b.issuer===b.holder)throw Error('SERVICE_OWNER');if(!Number.isSafeInteger(b.issued_at)||b.issued_at<0||!Number.isSafeInteger(b.expires_at)||b.expires_at<=b.issued_at||b.expires_at>b.issued_at+30)throw Error('SERVICE_EXPIRY');if(typeof b.can_s_turn!=='boolean'||typeof b.can_relay_blob!=='boolean'||b.can_relay_blob&&!b.can_s_turn)throw Error('SERVICE_CAPABILITY');const u=new URL(b.signaling_wss);if(u.protocol!=='wss:'||u.username||u.password||u.hash||typeof b.signaling_wss!=='string'||b.signaling_wss.length>2048||/[^\x21-\x7e]/.test(b.signaling_wss))throw Error('SERVICE_URL');return new TextEncoder().encode('D-MASH|NODE-SERVICE|V4|SERVICE_V1\0'+g.DmashSecureSession.canonical(b));}
 function verify(e,{now,issuer,holder,transcript_hash,challenge,signaling_wss}){if(!e||Object.keys(e).sort().join(',')!=='body,signature')throw Error('SERVICE_ENVELOPE');const b=e.body,raw=bodyBytes(b);for(const [k,v]of Object.entries({issuer,holder,transcript_hash,challenge,signaling_wss}))if(b[k]!==v)throw Error('SERVICE_CONTEXT');if(!Number.isSafeInteger(now)||b.issued_at>now||b.expires_at<=now)throw Error('SERVICE_EXPIRED');g.DmashRouteDiscoveryV4.validateEd25519SignatureEncoding(e.signature);if(!g.nacl.sign.detached.verify(raw,bytes(e.signature),bytes(issuer)))throw Error('SERVICE_SIGNATURE');return Object.freeze({...b});}
 g.DmashNodeServiceDescriptorV4=Object.freeze({bodyBytes,verify});if(typeof module!=='undefined')module.exports=g.DmashNodeServiceDescriptorV4;
})(globalThis);

function check(v,name){if(!v)throw Error(name);print('PASS '+name);}
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const msg=new TextEncoder().encode('D-MASH тест 🔐');
check(new TextDecoder().decode(msg)==='D-MASH тест 🔐','UTF8 synthetic adapter');
const sign=nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));const signature=nacl.sign.detached(msg,sign.secretKey);
check(nacl.sign.detached.verify(msg,signature,sign.publicKey),'unchanged TweetNaCl Ed25519');
check(hex(DmashResourcePow.sha256(new TextEncoder().encode('abc')))==='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','unchanged resource SHA256 vector');
check(hex(DmashBlake3.blake3(new Uint8Array()))==='af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262','unchanged BLAKE3 vector');
const key=nacl.box.keyPair();const blob=DmashRecipientPayloadV4.sealPayload(key.publicKey,'opaque тест');const opened=DmashRecipientPayloadV4.openPayload([key.secretKey],blob);
check(opened.status==='accepted'&&opened.payload==='opaque тест','unchanged recipient payload seal/open');
check(typeof DmashNodeRoutingV4==='function'&&typeof DmashNodeLocalOwnershipV4==='function','routing and ownership loaded');
print('Loaded 25 unchanged source modules; NO transport/storage/Android PASS');
