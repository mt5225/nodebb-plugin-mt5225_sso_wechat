do (module) ->
  'use strict'

  ###
    Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
    hook up NodeBB with your existing OAuth endpoint.

    Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
        or "oauth2" section needs to be filled, depending on what you set "type" to.

    Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

    Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
        a format accepted by NodeBB. Instructions are provided there. (Line 137)

    Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
  ###

  User = module.parent.require('./user')
  Groups = module.parent.require('./groups')
  meta = module.parent.require('./meta')
  db = module.parent.require('../src/database')
  passport = module.parent.require('passport')
  fs = module.parent.require('fs')
  path = module.parent.require('path')
  nconf = module.parent.require('nconf')
  winston = module.parent.require('winston')
  async = module.parent.require('async')
  emojiText = module.parent.require("emoji-text");
  constants = Object.freeze(
    type: 'oauth2'
    name: 'aghchina'
    oauth2:
      authorizationURL: 'http://qa.aghchina.com.cn:3008/dialog/authorize'
      tokenURL: 'http://qa.aghchina.com.cn:3008/oauth/token'
      clientID: 'ward-steward-2'
      clientSecret: 'something truly secret'
    userRoute: 'http://qa.aghchina.com.cn:3008/api/userinfo')
  configOk = false
  OAuth = {}
  passportOAuth = undefined
  opts = undefined
  if !constants.name
    winston.error '[sso-oauth] Please specify a name for your OAuth provider (library.js:32)'
  else if !constants.type or constants.type != 'oauth' and constants.type != 'oauth2'
    winston.error '[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)'
  else if !constants.userRoute
    winston.error '[sso-oauth] User Route required (library.js:31)'
  else
    configOk = true

  OAuth.getStrategy = (strategies, callback) ->
    if configOk
      passportOAuth = require('passport-oauth')['OAuth2Strategy']
      if constants.type == 'oauth2'
        # OAuth 2 options
        opts = constants.oauth2
        opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback'

        passportOAuth.Strategy::userProfile = (accessToken, done) ->
          @_oauth2.get constants.userRoute, accessToken, (err, body, res) ->
            if err
              return done(new InternalOAuthError('failed to fetch user profile', err))
            try
              json = JSON.parse(body)
              console.log json
              OAuth.parseUserReturn json, (err, profile) ->
                if err
                  return done(err)
                profile.provider = constants.name
                done null, profile
                return
            catch e
              done e
            return
          return

      passport.use constants.name, new passportOAuth(opts, (token, secret, profile, done) ->
        OAuth.login profile, (err, user) ->
          if err
            return done(err)
          done null, user
          return
        return
      )
      strategies.push
        name: constants.name
        url: '/auth/' + constants.name
        callbackURL: '/auth/' + constants.name + '/callback'
        icon: 'fa-circle-thin'
        scope: (constants.scope or '').split(',')
      callback null, strategies
    else
      callback new Error('OAuth Configuration is invalid')
    return

  OAuth.parseUserReturn = (data, callback) ->
    profile = {}
    console.log data
    profile.openid = data.user_id
    profile.displayName = data.name
    #profile.emails = [ { value: 'users@aghchina.com.cn' } ]
    profile.avatar = data.avatar
    console.log '===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n==='
    callback null, profile
    return

  OAuth.login = (payload, callback) ->
    console.log payload
    username = emojiText.convert(payload.displayName)
    console.log "username =  #{username}"
    OAuth.getUidByOpenID payload.openid, (err, uid) ->
      if err
        return callback(err)
      if uid != null
        # Existing User
        console.log("found existing user " + uid);
        User.setUserField uid, 'username', username
        User.setUserField uid, 'fullname', username
        User.setUserField uid, 'picture', payload.avatar
        User.setUserField uid, 'uploadedpicture', payload.avatar
        callback null, uid: uid
      else
        # New User
        User.create {
          username: username
          #email: payload.emails
        }, (err, uid) ->
          console.log("create new user with id " + uid);
          db.setObjectField constants.name + 'Id:uid', payload.openid, uid
          User.setUserField uid, 'fullname', username
          User.setUserField uid, 'picture', payload.avatar
          User.setUserField uid, 'uploadedpicture', payload.avatar
          if err
            return callback(err)
          callback null, uid: uid 
      
    

  OAuth.getUidByOpenID = (openid, callback) ->
    db.getObjectField constants.name + 'Id:uid', openid, (err, uid) ->
      console.log("find uid=" + uid);
      if err
        return callback(err)
      callback null, uid
      return
    return

  OAuth.deleteUserData = (uid, callback) ->
    async.waterfall [
      async.apply(User.getUserField, uid, constants.name + 'Id')
      (oAuthIdToDelete, next) ->
        db.deleteObjectField constants.name + 'Id:uid', oAuthIdToDelete, next
        return
    ], (err) ->
      if err
        winston.error '[sso-oauth] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err
        return callback(err)
      callback null, uid
      return
    return

  module.exports = OAuth
  return