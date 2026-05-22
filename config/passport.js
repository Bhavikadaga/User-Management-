const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../model/user.js');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
},
async(accessToken, refreshToken, profile, done) =>{
    try{
        const email= profile.emails[0].value;
        const picture = profile.photos[0].value;
        let user = await User.findOne({ email });

        if(user){
            if(!user.providers.google.id){
                user.providers.google.id = profile.id;
                user.providers.google.picture = picture;
                await user.save();
            }
        }else{
            user = await User.create({
                name: profile.displayName,
                email,
                isEmailVerified: true,
                providers: {
                    google: { id: profile.id, picture }
                }
            });
        }
        return done(null, user);
    }catch(err){
        return done(err, null);
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'http://localhost:5000/auth/github/callback',
    scope: ['user:email']
},
async (accessToken, refreshToken, profile, done) =>{
    try{
        const email = profile.emails?.[0]?.value;
        let user = await User.findOne({ email });
        if(user){
            if(!user.providers.github.id){
                user.providers.github.id = profile.id,
                user.providers.github.picture = picture,
                await user.save()
            }
        }else{
            user = await User.create({
                name: profile.displayName || profile.username,
                email,
                isEmailVerified: true,
                providers: {
                    github:{id: profile.id, picture}
                }
            });
        }
        return done(null, user);
    }catch(err){
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async (id, done) =>{
    try{
        const user = await User.findById(id);
        done(null, user);
    }catch(err){
        done(err, null);
    }
});
module.exports = passport;