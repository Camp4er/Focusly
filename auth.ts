import NextAuth from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import { ConvexAdapter } from "./app/ConvexAdapter";
import { importPKCS8, SignJWT } from "jose";

if(process.env.CONVEX_AUTH_PRIVATE_KEY === undefined) {
  throw new Error("Missing CONVEX_AUTH_PRIVATE_KEY");
}

if(process.env.JWKS === undefined) {
  throw new Error("Missing JWKS");
}


const CONVEX_SITE_URL= process.env.NEXT_PUBLIC_CONVEX_URL!. replace(/.cloud$/,".site")
 
export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    //google auth
    GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,

        //so that client can only sign in if they agree with the terms and conditions
        authorization: { params: { prompt: "consent"}}
    })
  ],
  adapter: ConvexAdapter,
  callbacks: {
    async session({session}) {
      const privateKey = await importPKCS8(process.env.CONVEX_AUTH_PRIVATE_KEY!, 'RS256');

      const convexToken = await new SignJWT({
        sub: session.userId
      }).setProtectedHeader({ alg: "RS256"})
      .setIssuedAt()
      .setIssuer(CONVEX_SITE_URL)
      .setAudience('convex')
      .setExpirationTime('1hr')
      .sign(privateKey);

      return {...session, convexToken}
      
    }, 
  },
});