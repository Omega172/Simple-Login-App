import PassportLocal from "passport-local";
const LocalStrategy = PassportLocal.Strategy;

export function Initialize(Passport, AuthFunc, FindByID) {

Passport.use(new LocalStrategy({}, AuthFunc));

Passport.serializeUser((user, done) => done(null, user.id));
Passport.deserializeUser((id, done) => { 
    const User = FindByID(id);
    return done(null, User);
});
}