/**
 * @fileOverview Protocol to communicate with server
 * @version 1.0.0
 */

//TODO should i use TweetNaCl for crypto
export default class ZeroProtocol {
    constructor() {
        //Check Support
        var cryptoObject = crypto.subtle;

        if (!cryptoObject) {
            throw "Web Crypto is not supported";
        }

        // register the main thread to send entropy or a Web Worker to receive
        // entropy on demand from the main thread
        forge.random.registerWorker(self);
    }

    //used to check compatibility with server version
    VersionString = "1.0.0";

    ConnectionConfig = {
        APIPath: "",
        UseCookieSession: true,
    };

    //Callback Functions_______________________________________
    LogOutCallback = null;
    ReadyEvent = function () { };
    Ready = false;
    //Function called when unable to login
    AuthFail = null;
    RefreshUserPage = null;



    //Function called to report errors
    Alert = (x) => {
        alert(x);
    };

    SupportedTypes = ["Post"]; //todo possibly remove this
    SecurityLevelsNames = ["Private", "freinds", "Unsinged", "Public", "PublicLink"];

    AccountInfo = {};
    PeopleCashe = [];

    state = {
        CSRFToken: "",
        Username: "",
        Waiting: false,
        WaitingCallback: null
    };

    Cryptostate = {
        StorageKey: "",
        KeyCSRFToken: "",
        ContentPublicKey: "",
        ContentPrivateKey: "",
        PublicPublicKey: "",
        PublicPrivateKey: ""
    };

    /**
     * Initialises Zero and calls this.ReadyEvent(); when finished, Sets this.Ready
     */
    Init() {
        this.Ready = true;
        if (this.ReadyEvent) {
            this.ReadyEvent();
        }
    };

    SetReadyEvent(Callback) {
        if (this.Ready) {
            Callback();
        } else {
            this.ReadyEvent = Callback;
        };
    };


    // Secures the local key by encrypting it with the Key CSRF Token
    SecureKey(Key, KeyCSRFToken) {
        //todo
    };



    /**
     *caculates the Key used to decrypt the account private keys
     * @param {string} Password The users password
     * @returns {string} A key derrived from the password
     */
    KeyDerivation(Password) {
        var salt = "";
        var numIterations = 10;
        var AccountKey = forge.pkcs5.pbkdf2(Password, salt, numIterations, 16);
        return AccountKey;
    };

    /**
     *This function caculates the hash-based  code used to log-in with sha3
     * @param {string} Password The users password
     * @returns {string} A Hash derrived from the password
     */
    LoginHash(Password) {
        return sha3_256(Password);
    };


    SighHash(Content) {
        return "";
        //todo: Finish this;
    };


    //____________________________________________________________________________________________


    /**
     *Check if the user as stored credentials
     * @returns {boolean} credentials are valid
     */
    Persisting() {
        //todo need to check if the user has logged out and back in in a diffrent tab
        if (!this.Ready) {
            this.Alert("not ready");
            return false;
        }

        if (!this.Cryptostate.ContentPublicKey) {
            if (typeof Storage === "undefined") return false;

            var InfoText = localStorage.ZeroAccount;
            if (!InfoText) return false;
            return true;

        } else {
            return true;
        }

        //TODO clear persistance if logged out but still persistant
    };


    /**
     *Load stored credentials from local storage if possible
     * @returns {promice} promice 
     */
    LoadPersistant() {

        if (typeof Storage === "undefined") return ErrorPromice(false);
  

        if (this.CrossDomain) {
            this.CookieSession = localStorage.getItem('ZeroCookieSession');
        }

        var InfoText = localStorage.getItem('ZeroAccount');
        if (!InfoText) return ErrorPromice(false);

      return  this.AjaxCall("/api/StorageKey", "GET", null).then(  (response) => {
            try {


                var Key = forge.util.decode64(response.StorageKey + "") + "";
                var DecryptedData = this.DecryptBlockKey(InfoText, Key);
                if (!DecryptedData) {
                    this.ClearPersistant();
                    return false;
                }

                var ZeroInfo = DecryptedData;

                if (typeof (ZeroInfo) === "undefined") {
                    this.ClearPersistant();
                    return false;
                }

                if (!ZeroInfo.ContentPrivateKey || !ZeroInfo.ContentPublicKey) {
                    this.ClearPersistant();
                    return false;
                }

                if (!ZeroInfo.PublicPublicKey || !ZeroInfo.PublicPrivateKey) {
                    this.ClearPersistant();
                    return false;
                }

                this.AccountInfo = ZeroInfo;

                if (!this.LoadCryptoState()) {
                    this.AccountInfo = {};
                    this.ClearPersistant();
                    return false;
                }

                if (document.cookie.indexOf("ZeroPersisting=") === -1) {
                    document.cookie = "ZeroPersisting=True";
                }
                this.WatchSessionStorage();
            } catch (e) {
                this.LogOut();
                console.error(e, e.stack);
                return false;
            }
            return true;
        }).catch((err) => {
                this.LogOut();
                deferred.reject(false);
        });

    };

    /**
     *decrypt keys and Crypto infomation from state
     * @returns {boolean} sucesssfull
     */
    LoadCryptoState() {
        if (!this.AccountInfo.ContentPrivateKey || !this.AccountInfo.ContentPublicKey) {
            return false;
        }

        if (!this.AccountInfo.PublicPublicKey || !this.AccountInfo.PublicPrivateKey) {
            return false;
        }

        this.Cryptostate = {
            KeyCSRFToken: "",
            ContentPublicKey: "",
            ContentPrivateKey: "",
            PublicPublicKey: "",
            PublicPrivateKey: ""
        };

        var rsa = forge.pki.rsa;
        var pki = forge.pki;
        var asn1 = forge.asn1;

        try {

            this.Cryptostate.ContentPublicKey = pki.publicKeyFromAsn1(asn1.fromDer(forge.util.decode64(this.AccountInfo.ContentPublicKey)));
            this.Cryptostate.ContentPrivateKey = pki.privateKeyFromAsn1(asn1.fromDer(forge.util.decode64(this.AccountInfo.ContentPrivateKey)));
            this.Cryptostate.PublicPublicKey = pki.publicKeyFromAsn1(asn1.fromDer(forge.util.decode64(this.AccountInfo.PublicPublicKey)));
            this.Cryptostate.PublicPrivateKey = pki.privateKeyFromAsn1(asn1.fromDer(forge.util.decode64(this.AccountInfo.PublicPrivateKey)));

        } catch (err) {
            console.log(err);
            return false;
        }
        return true;

    };

    /**
     *Callback called when storage has been changed. used to logout if logged in in another tab
     *
     */
    StorageChanged() {
        try {
            location.reload();
            this.StopWatch();
        } catch (err) {
            console.error(err);
        }
    }

    /**
     *Removes storage listerner
     */
    StopWatch() {
        window.removeEventListener('storage', this.StorageChanged);
    };

    /**
     *Adds storage listerner
     */
    WatchSessionStorage() {
        window.addEventListener('storage', this.StorageChanged, false);
    };



    /**
     * Stores account infomation and crypto to local storage and sets cookie
     * @returns {boolean} scuseessfull
     * 
     */
    Persist() {

        if (!this.Ready) {
            return false;
        }
        //**todo make cookie domian spesific
        if (typeof (Storage) !== "undefined") {

            var StorageData = this.AccountInfo;
            var EncryptedStorage = this.EncryptBlock(StorageData, this.Cryptostate.StorageKey);
            if ((!localStorage.ZeroAccount || localStorage.ZeroAccount === "")) {
                localStorage.ZeroAccount = EncryptedStorage;
            }
            document.cookie = "ZeroPersisting=True" + ";path=/;SameSite=Strict";
            this.WatchSessionStorage();
        } else {
            return false;
        }
    };




    /**
     * clears localstorage and cookie
     */
    ClearPersistant() {
        try {
            localStorage.removeItem('ZeroAccount');
            localStorage.removeItem('randid');
            localStorage.removeItem('ZeroCookieSession');

            localStorage.clear();
            if (getCookie("ZeroPersisting")) {
                document.cookie = "ZeroPersisting" + "=" +
                    ";expires=Thu, 01 Jan 1970 00:00:01 GMT;";
            }
        } catch (err) {
            console.error(err);
        }
    };

    /**
     * log out locally, clears persistant storage and calls the authFail function
     */
    LogOut() {

        if (typeof this.LogOutCallback === "function") {
            try {
                this.LogOutCallback();
            } catch (err) {
                console.error(err);
            }
        }

        this.ClearPersistant();
        if (!this.AccountInfo.ContentPrivateKey || !this.AccountInfo.ContentPublicKey) {

        }

        this.state = {};
        this.AccountInfo = {};
        this.Cryptostate = {};
        this.PeopleCashe = [];
    };



    /**
     * Helper to perfrom ajax call. On 403 logout is called
     * @param {string} Address url
     * @param {string} Method http method
     * @param {Object} Data object to sent
     * @param {Function} Callback function to call on success
     * @returns {promice} promice of ajax
     */
    AjaxCall(Address, Method, Data) {

        var DataString = null;
        var contentType;


        let Options = {
            method: Method,
            cache: 'no-cache',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            dataType: "json",
            redirect: 'error'
        };


        let URL = this.ConnectionConfig.APIPath + Address;
        if (Method == "POST" && Data) {
            Options.body = JSON.stringify(Data);
        }else if (Method == "GET" && Data) {
            URL = URL + new URLSearchParams(Data);
        }



        var resultPromice = fetch(URL, Options).catch((error) => {
            console.error('Error:', error);
        }).then((Result) => {
            if (Result.status === 403) {
                this.LogOut();
                throw Error("not logged in");
            }

            if (!Result.ok) {
                throw Error(Result.status);
            }
            return Result.json();
            
        });

        return resultPromice;
        
    };


    Login(Username, Password) {

        if (Username === null || Username.length === 0 || Password === null || Password.length === 0) {
            return ErrorPromice("Missing infomation");
        }

        this.StopWatch();
        this.Cryptostate.StorageKey = forge.random.getBytesSync(16);

        const UsernameHash = sha3_256(Username);
        const AccountKey = this.KeyDerivation(Password);
        const Hash = this.LoginHash(Password);
        var LoginData = {
            'Username': UsernameHash,
            'Password': Hash,
            StorageKey: forge.util.encode64(this.Cryptostate.StorageKey)
        };

        return this.AjaxCall("/api/login", "POST", LoginData).then( (response) => {
            var Data = response;
            if (Data.AccountData === undefined) {
                this.state.Waiting = false;
                throw "Unable to get account data";
            }
            var AccountData = new String(Data.AccountData);
            //todo possibly need to have some form of error checking

            var Parts = AccountData.split("*");

            var IV = forge.util.decode64(Parts[0]);
            var encryptedData = forge.util.decode64(Parts[1]);

            var decipher = forge.aes.createDecryptionCipher(AccountKey, 'CBC');
            decipher.start(IV);
            var buffer = forge.util.createBuffer(encryptedData);
            decipher.update(buffer);
            decipher.finish();
            var data = decipher.output.data;
            this.AccountInfo = JSON.parse(data);
            this.AccountInfo.AccountID = Data.AccountID;
            this.AccountInfo.PublicPublicKey = Data.PublicKey;
        });

    };



    Create(Username, Password, PublicName, captcha) {

        if (!Username || !Password) {
            return ErrorPromice("Missing infomation");
        }

        this.StopWatch();
        Username = Username + "";
        Password = Password + "";

        if (Username === null || Username.length === 0 || Password === null || Password.length === 0 || captcha === null || captcha.length === 0) {
            return ErrorPromice("Missing infomation");
        }

        if (PublicName) {
            PublicName = PublicName + "";
            if (PublicName.lenght > 12) {
                return ErrorPromice("Public name is too long");
            }
        }
        var deferred = $.Deferred();

        try {
            var rsa = forge.pki.rsa;
            var pki = forge.pki;
            var asn1 = forge.asn1;

            var iv = forge.random.getBytesSync(16);
            var salt = "";
            var AccountKey = this.KeyDerivation(Password);

        } catch (err) {
            console.log(err);
            deferred.reject(err);
        }


        rsa.generateKeyPair({
            bits: 2048,
            workers: -1
        }, (err, Publickeypair) => {

            if (err) {
                deferred.reject(err);
                return;
            }

            rsa.generateKeyPair({
                bits: 2048,
                workers: -1
            }, (err, keypair) => {

                if (err) {
                    deferred.reject(err);
                    return;
                }

                try {

                    this.AccountInfo = AccountInfo;
                    var ContentPublicKey = forge.util.encode64(asn1.toDer(pki.publicKeyToAsn1(keypair.publicKey))
                        .getBytes());
                    var ContentPrivateKey = forge.util.encode64(asn1.toDer(pki.privateKeyToAsn1(keypair.privateKey))
                        .getBytes());
                    var PublicPublicKey = forge.util.encode64(asn1.toDer(pki.publicKeyToAsn1(Publickeypair.publicKey))
                        .getBytes());
                    var PublicPrivateKey = forge.util.encode64(asn1.toDer(pki.privateKeyToAsn1(Publickeypair.privateKey))
                        .getBytes());

                    var AccountInfo = {
                        Username: Username,
                        'ContentPrivateKey': ContentPrivateKey,
                        'ContentPublicKey': ContentPublicKey,
                        'PublicPrivateKey': PublicPrivateKey
                    };


                    var cipher = forge.aes.createEncryptionCipher(AccountKey, 'CBC');
                    cipher.start(iv);
                    cipher.update(forge.util.createBuffer(JSON.stringify(AccountInfo)));
                    cipher.finish();
                    var encrypted = cipher.output;

                    var AccountData = forge.util.encode64(iv) + "*" + forge.util.encode64(encrypted.getBytes());

                    var UsernameHash = sha3_256(Username);

                    //TODO need to add a check to the decrypted data to ensure that the decrypted data is correct.
                    var Submitdata = {
                        'Username': UsernameHash,
                        'Password': this.LoginHash(Password),
                        'AccountData': AccountData,
                        Publickey: PublicPublicKey,
                        'captcha': captcha,
                        PublicName: PublicName
                    };

                } catch (err) {
                    console.log(err);
                    deferred.reject(err);
                    return;
                }


                //todo this
                    this.AjaxCall("/api/create", "POST", Submitdata).then( (response) => {
                    deferred.resolve();
                })
                        .catch((err) => {
                        deferred.reject(err);
                    });

            });
        });

        return deferred.promise();
    };




    StoreObject(Object, SecurityLevel, UseSecurityToken) {

        var deferred = $.Deferred();

        try {


            var rsa = forge.pki.rsa;


            var Result = {};
            Result.SecurityLevel = SecurityLevel;
            var SecurityToken;
            var Key;
            if (SecurityLevel < 3) {

                Key = forge.random.getBytesSync(16);
                var encryptedKey = forge.pki.rsa.encrypt(Key, this.Cryptostate.ContentPrivateKey, 0x01);
                if (UseSecurityToken) {
                    SecurityToken = forge.util.encode64(encryptedKey);
                    Result.Key = "";
                } else {
                    Result.Key = forge.util.encode64(encryptedKey);
                }
            }

            if (!Object.Postdata) {
                Object.Postdata = {};
            }

            if (Object.Postdata) {
                Result.PostInfo = this.EncryptPostPart(Object.Postdata, SecurityLevel, Key);
            }

            if (Object.Small) {
                Result.Small = this.EncryptPostPart(Object.Small, SecurityLevel, Key);
            }



            if (Object.Resource && Object.Resource.Data && !isArrayEmpty(Object.Resource.Data)) {
                Result.Data = this.EncryptPostPart({
                    Data: Object.Resource.Data
                }, SecurityLevel, Key);
            }

            var d = new Date();
            Result.date = d.getUTCDate();

        } catch (err) {
            return ErrorPromice(err);
        }
        this.AjaxCall("/api/object", "POST", Result).then( (response) => {
            if (!response || !response.ID) deferred.reject("missing responce");
            if (SecurityToken) {
                deferred.resolve({
                    ID: response.ID,
                    Token: SecurityToken
                });
            } else {
                deferred.resolve(response.ID);
                SecurityToken
            }


        })
            .catch((err) => {
                deferred.reject(err);
            });
        return deferred;
    };




    CreatePost(PostType, PostInfo, Small, Resource, SecurityLevel, OtherUser, SecurityToken) {


        if (!this.SupportedTypes.includes(PostType)) {
            return ErrorPromice("Not Ready");
        }

        try {
            var rsa = forge.pki.rsa;

            var Result = {
                PostType: PostType,
                SecurityLevel: SecurityLevel,
                Key: null
            };
            var Key;
            if (SecurityLevel < 3) {
                Key = forge.random.getBytesSync(16);
                var encryptedKey = forge.pki.rsa.encrypt(Key, this.Cryptostate.ContentPrivateKey, 0x01);
                Result.Key = forge.util.encode64(encryptedKey);
            }

            if (!PostInfo) {
                PostInfo = {};
            }

            if (SecurityLevel < 3) {
                let CKey = forge.util.encode64(forge.random.getBytesSync(16));
                PostInfo.Ckey = CKey;
            }

            if (PostInfo) {
                Result.PostInfo = this.EncryptPostPart(PostInfo, SecurityLevel, Key);
            }

            if (Small) {
                Result.Small = this.EncryptPostPart(Small, SecurityLevel, Key);
            }

            if (Resource && !isArrayEmpty(Resource)) {
                Result.Data = this.EncryptPostPart({
                    Data: Resource
                }, SecurityLevel, Key);
            }

            if (OtherUser) {
                //**todo Other USer
            }

            var d = new Date();
            Result.date = d.getUTCDate();

        } catch (err) {
            console.log(err);
            return ErrorPromice(err);
        }
        return this.AjaxCall("/api/post", "POST", Result).then( (response) => {
            this.RefreshUserPage(this.AccountInfo.AccountID);
        });
    };

    GetFeed(date) {
        let Query = {};
        if (date) {
            var Timecode = parseInt(date);
            if (!isNaN(Timecode)) {
                Query.date = Timecode;
            } else {
                //Query.date = date.getTime();
                throw "unknow date format:(" + date + ")";
            }
        }

        return this.AjaxCall("/api/feed", "GET", Query, (response) => {
            var Data = response;
            return Data;
            //todo should do some validation here
        });
    };



    GetFriendRequests() {

        return this.AjaxCall("/api/Requests", "GET", null).then( (response) => {
            var Data = response;
            return Data;
        });
    };



    GetFriends() {

        return this.AjaxCall("/api/friends", "GET", null).then( (response) => {
            var Data = response;
            return Data;
        });
    };

    GetUserFriends(UserID) {

        if (UserID === this.AccountInfo.AccountID) {
            return this.GetFriends();
        }

        return this.AjaxCall("/api/userfriends", "GET", {
            "UserID": UserID
        }).then( (response) => {
            var Data = response;
            return Data;
        });
    };


    GetUserPosts(UserID, date) {

        let Query = {};
        if (date) {
            var Timecode = parseInt(date);
            if (!isNaN(Timecode)) {
                Query.date = Timecode;
            } else {
                //Query.date = date.getTime();
                throw "unknow date format:(" + date + ")";
            }
        }

        UserID = parseInt(UserID);
        if (!(UserID > 0)) {
            return ErrorPromice("invalid ID");
        }

        return this.AjaxCall("/api/User/" + UserID + "/Posts", "GET", Query).then(  (response) => {
            var Data = response;
            return Data;
        });
    };


    PostComment(Post, Comment) {

        if (!Post) {
            return ErrorPromice("invalid Post");
        }

        var PostID = Post.PostID;

        if (!(PostID > 0)) {
            return ErrorPromice("invalid Post ID for Comment");
        }

        if (!Post.Postdata) {
            return ErrorPromice("missing CKey for Comment");
        }

        var CKey = Post.Postdata.Ckey;
        if (!CKey) {
            return ErrorPromice("missing CKey for Comment");
        }
        if (!Comment) {
            return ErrorPromice("missing Comment");
        }

        let CommentKey = forge.random.getBytesSync(16);

        CKey = forge.util.decode64(CKey);




        let EncryptedContent = this.EncryptBlock(JSON.stringify(Comment), CommentKey);
        let Key = this.EncryptBlock(CommentKey, CKey);
        return this.AjaxCall("/api/post/" + PostID + "/comments", "POST", {
            Content: EncryptedContent,
            Key: Key
        }).then(  (response) => {

        });
    };



    GetComments(Post) {

        if (!Post) {
            return ErrorPromice("invalid Post");
        }

        var PostID = Post.PostID;

        if (!(PostID > 0)) {
            return ErrorPromice("invalid Post ID for Comments");
        }

        if (!Post.Postdata) {
            return ErrorPromice("missing CKey for Comments");
        }

        var CKey = Post.Postdata.Ckey;

        if (!CKey) {
            return ErrorPromice("missing CKey for Comments");
        }
        CKey = forge.util.decode64(CKey);
        return this.AjaxCall("/api/post/" + PostID + "/comments", "GET", null).then(  (response) => {

            if (!response) return [];



            for (const element of response) {
                try {

                    let CommentKey = this.DecryptBlockKey(element.Key, CKey);

                    element.Content = JSON.parse(this.DecryptBlockKey(element.Content, CommentKey));
                    element.failed = false;
                    if (element.Content === null) {
                        element.failed = true;
                    }

                } catch {
                    element.failed = true;
                }
            }

            return response;

        });
    };



    GetPost(PostID, OptionalKey) {

        PostID = parseInt(PostID);
        if (!(PostID > 0)) {
            return ErrorPromice("invalid ID");
        }

        return this.AjaxCall("/api/post/" + PostID, "GET", null).then(  (response) => {

            var Data = response[0];
            var Post = this.DecryptPost(Data, OptionalKey);
            if (Post === null) {
                throw "Unable to decrypt";
            } else {
                return Post;
            }
        });
    };


    GetPostBody(PostID, OptionalKey) {
        PostID = parseInt(PostID);
        if (!(PostID > 0)) {
            return ErrorPromice("invalid ID");
        }

        return this.AjaxCall("/api/post/" + PostID + "/body", "GET", null).then(  (response) => {
            var Data = response[0];
            var Post = this.DecryptPost(Data, OptionalKey);
            if (Post === null) {
                return null;
            } else {
                return Post;
            }
        });
    };


    GetPostSmall(PostID, OptionalKey) {
        PostID = parseInt(PostID);
        if (!(PostID > 0)) {
            return ErrorPromice("invalid ID");
        }

        return this.AjaxCall("/api/post/" + PostID + "/Small", "GET", null).then(  (response) => {
            var Data = response[0];
            var Post = this.DecryptPost(Data, OptionalKey);
            if (Post === null) {
                return null;
            } else {
                return Post;
            }
        });
    };


    DecryptBlock(Data, EncryptedKey, PublicKey) {
        if (!PublicKey) throw "Invalid PublicKey Key";
        if (!EncryptedKey) throw "Invalid EncryptedKey";
        var Key;
        if (PublicKey.decrypt) {
            Key = PublicKey.decrypt(forge.util.decode64(EncryptedKey));
        } else {
            Key = forge.pki.rsa.decrypt(forge.util.decode64(EncryptedKey), PublicKey, 0x01);
        }

        return this.DecryptBlockKey(Data, Key);
    };

    DecryptBlockKey(Data, Key) {
        if (!Key || Key == null) throw "Invalid Key (Missing)";
        if (!Data || Data == null) throw "Invalid Data (Missing)";

        var Parts = Data.split("*");
        if (Parts.length !== 2) throw "Invalid Data Block format:" + Data;
        var encryptedData = forge.util.decode64(Parts[1]);

        var IV = forge.util.decode64(Parts[0]);

        var decipher = forge.aes.createDecryptionCipher(Key, 'CBC');
        decipher.start(IV);
        var buffer = forge.util.createBuffer(encryptedData);
        decipher.update(buffer);
        decipher.finish();

        var Result = forge.util.decodeUtf8(decipher.output.data);

        return JSON.parse(Result);
    };

    EncryptBlock(Data, Key) {
        //todo should i use RSA-KEM Key encapsulation
        var SmallIV = forge.random.getBytesSync(16);
        var Smallcipher = forge.aes.createEncryptionCipher(Key, 'CBC'); //todo should probally use a diffrent key
        Smallcipher.start(SmallIV);
        var buffer = forge.util.createBuffer(JSON.stringify(Data), 'utf8');

        Smallcipher.update(buffer);

        Smallcipher.finish();
        var Result = forge.util.encode64(SmallIV) + "*" + forge.util.encode64(Smallcipher.output.getBytes());
        return Result;
    };




    EncryptPostPart(Data, SecurityLevel, Key) {
        if (SecurityLevel < 3) {
            if (!Key) {
                return null;
            }
            try {
                var Result = this.EncryptBlock(Data, Key);

                if (SecurityLevel < 2) {
                    Result.Signature = this.SighHash(Result);
                }
                return Result;

            } catch (e) {
                console.error(e, e.stack);
                return null;
            }
        } else {
            return Data;
        }
    };

    DecryptPostPart(Data, SecurityLevel, EncryptedKey, PublicKey) {

        if (!Data || Data == null) {
            console.log("DecryptPostPart: no Data");
            return null;
        }

        if (SecurityLevel < 3) {
            if (!PublicKey) {
                console.log("no public key");
                return null;
            }
            try {
                return this.DecryptBlock(Data, EncryptedKey, PublicKey);
            } catch (e) {
                console.error(e, e.stack);
                return null;
            }
        } else {
            return JSON.parse(Data);
        }

    };

    DecryptPost(Post, OptionalKey) {

        var Result = {};

        if (typeof Post === 'undefined' || Post === null) {
            console.log("Post Failed: no Post");
            return {
                failedReason: "No Post",
                failed: true
            };
        }
        Result.PostID = Post.PostID;
        Result.AccountID = Post.AccountID;
        Result.date = new Date(Post.Date * 1000);
        Result.failed = false;
        Result.SecurityLevel = Post.SecurityLevel;
        var ContentPublicKey = this.ContentPublicKeyFromCache(Result.AccountID);


        if (!Post.PostKey && !!OptionalKey) {
            Post.PostKey = OptionalKey;
        }

        if (!Post.PostKey && Result.SecurityLevel < 3) {
            console.log("Post Failed: no Post Key");
            Result.failedReason = "no Post Key";
            Result.failed = true;
            return Result;
        }



        if (ContentPublicKey === null && Result.SecurityLevel < 3) {

            console.log("Post Failed: no Public Key");
            Result.failedReason = "no Public Key";
            ContentPublicKey = this.ContentPublicKeyFromCache(Result.AccountID);
            Result.failed = true;
            return Result;
        }

        var Key = Post.PostKey;

        if (typeof Post.Postdata !== 'undefined' && Post.Postdata !== null) {

            let Part = this.DecryptPostPart(Post.Postdata, Post.SecurityLevel, Key, ContentPublicKey);
            if (Part === null) {
                console.log("Post Failed: Postdata Decrypt failed");
                Result.failedReason = "Postdata Decrypt failed";
                Result.failed = true;
                return Result;
            } else {
                Result.Postdata = Part;
            }
        }

        if (typeof Post.SmallPost !== 'undefined' && Post.SmallPost !== null) {

            let Part = this.DecryptPostPart(Post.SmallPost, Post.SecurityLevel, Key, ContentPublicKey);
            if (Part === null) {
                console.log("Post Failed: SmallPost Decrypt failed");
                Result.failedReason = "SmallPost Decrypt failed";
                Result.failed = true;
                return Result;
            } else {
                Result.Small = Part;
            }
        }

        if (typeof Post.Post !== 'undefined' && Post.Post !== null) {

            let Part = this.DecryptPostPart(Post.Post, Post.SecurityLevel, Key, ContentPublicKey);
            if (Part === null) {
                console.log("Post Failed: Post Decrypt failed");
                Result.failedReason = "Post Decrypt failed";
                Result.failed = true;
                return Result;
            } else {
                Result.Resource = Part;
            }
        }

        return Result;
    };


    NamedPerson(Name) {

        var AID = parseInt(Name);

        if (AID) {

            var Result = this.PeopleCashe[parseInt(AID)];
            if (Result) {
                if (x.promise) { //Check if Differed
                    return Result;
                }
                return FinishedPromice(AID);
            }

        }

        return this.AjaxCall("/api/U/" + encodeURIComponent(Name), "GET", null).then(  (response) => {

            if (typeof response.AccountID === 'undefined' && response.AccountID === null) {
                throw "Unable to Find person";
            }

            if (this.PeopleCashe.includes(response.AccountID)) {
                CallBack(Person.AccountID);
            }

            var Person = this.PersonFromResponce(response);
            if (!Person) {
                throw "unable to find person";
            }
            return Person.AccountID;
        });

    };

    PreloadPerson(AccountID) {
        AccountID = parseInt(AccountID);
        if (isNaN(AccountID)) return ErrorPromice("Invalid id");

        var Result = this.PeopleCashe[AccountID];
        if (Result) {
            if (Result.promise) { //check if it is a jquery differed
                // Deferred
                return this.PeopleCashe[AccountID];
            }
            return FinishedPromice(AccountID);
        }

        Result = this.AjaxCall("/api/User/" + AccountID, "GET", null).then(  (response) => {
            if (typeof response.AccountID === 'undefined' && response.AccountID === null) {
                throw "person not found";
            }

            if (this.PersonFromResponce(response)) {
                return AccountID;
            } else {
                throw "person not found";
            }

        });
        this.PeopleCashe[AccountID] = Result;
        return Result;
    };


    PersonFromResponce(response) {

        const pki = forge.pki;
        const rsa = forge.pki.rsa;
        const asn1 = forge.asn1;

        if (!response) return null;

        var Person = {
            AccountID: parseInt(response.AccountID),
            AccountPost: null,
            ProfilePost: response.ProfilePost,
            Friend: response.Friend
        };

        if (typeof response.PublicName !== 'undefined' && response.PublicName !== null) {
            Person.PublicName = new String(response.PublicName);
            Person.PublicIdentificant = parseInt(response.PublicIdentificant);
        } else {
            Person.PublicName = null;
            Person.PublicIdentificant = null;
        }

        var AccountID = parseInt(response.AccountID);
        if (isNaN(AccountID)) {
            return null;
        }


        if (response.PublicKey) {
            Person.PublicKey = pki.publicKeyFromAsn1(asn1.fromDer(forge.util.decode64(response.PublicKey)));
        }

        if (!response.Friend) {
            Person.SentRequest = response.SentRequest;
            Person.FriendRequest = response.FriendRequest;
            Person.AcceptedRequest = response.AcceptedRequest;
            if (Person.AcceptedRequest && !Person.FriendRequest) {
                //todo deal with this;
                throw "Other has accepted Request";
            }
        } else {
            if (response.ContentKey && response.FriendshipKey) {
                let EncryptedKey = response.FriendshipKey;
                let ContentKey = this.DecryptBlock(response.ContentKey, EncryptedKey, this.Cryptostate.ContentPrivateKey);

                Person.ContentKey = pki.publicKeyFromAsn1(asn1.fromDer(forge.util.decode64(ContentKey)));
            }
        }

        if (response.DName) {
            Person.DName = response.DName;
        } else {
            Person.DName = null;
        }

        this.PeopleCashe[AccountID] = Person;

        if (response.Postdata !== null) {
            var Accountpost = this.DecryptPost(response);
            Accountpost.PostID = response.ProfilePost;
            if (Accountpost !== null && !Accountpost.failed) {
                this.PeopleCashe[AccountID].AccountPost = Accountpost;
            }
        }
        return Person;
    };


    generateRequest(UserID, Text) {
        const rsa = forge.pki.rsa;
        const pki = forge.pki;
        const asn1 = forge.asn1;


        var Secret = forge.random.getBytesSync(16);
        var EncryptedSecret = forge.util.encode64(this.Cryptostate.ContentPublicKey.encrypt(Secret));

        var ContentKey = this.Cryptostate.ContentPublicKey;
        var FriendKey = this.PublicKeyFromCache(UserID);
        if (!FriendKey) {
            throw "person not found";
        }


        var ContentPublicKey = forge.util.encode64(asn1.toDer(pki.publicKeyToAsn1(ContentKey))
            .getBytes());



        var Request = {
            Userid: this.AccountInfo.AccountID,
            ContentPublicKey: ContentPublicKey,
            Secret: forge.util.encode64(Secret)
        };

        var Key = forge.random.getBytesSync(16);
        var encryptedKey = forge.util.encode64(FriendKey.encrypt(Key));
        var EncryptedRequest = this.EncryptBlock(Request, Key);
        var Message = this.EncryptBlock(JSON.stringify({
            Text: Text,
            Secret: EncryptedSecret
        }), Key);

        //Secret: EncryptedSecret 


        var Result = {
            Key: encryptedKey,
            Data: EncryptedRequest,
            OtherID: UserID,
            Message: Message,
            Secret: EncryptedSecret
        };
        return Result;

    };


    RecieveRequest(Request) {
        const rsa = forge.pki.rsa;
        const pki = forge.pki;
        const asn1 = forge.asn1;

        try {

            if (!Request.Data) {
                throw "data not found";
            }

            if (!Request.Message) {
                throw "Message not found";
            }

            if (!Request.RequestKey) {
                throw "Key not found";
            }

            var Data = this.DecryptBlock(Request.Data, Request.RequestKey, this.Cryptostate.PublicPrivateKey);
            if (!Data) {
                throw "unable to decrypt";
            }

            if (Data.Userid !== Request.AccountID) {
                throw "invalid ID";
            }

            if (!Data.ContentPublicKey) {
                throw "invalid key";
            }

            var Key = forge.random.getBytesSync(16);
            var Freindship = this.EncryptBlock(Data.ContentPublicKey, Key);
            var EncryptedKey = forge.util.encode64(this.Cryptostate.ContentPublicKey.encrypt(Key));

            var Result = {
                OtherID: Data.Userid,
                Key: EncryptedKey,
                Data: Freindship,
                Message: {}
            };

        } catch (err) {
            return ErrorPromice(err);
        }

        return this.AjaxCall("/api/SaveFreind/", "POST", Result).then(  (response) => {
            this.RefreshPerson(Request.AccountID);
        });

    };


    SendFriend(UserID, Text) {

        if (UserID === this.AccountInfo.AccountID) {
            return ErrorPromice("cant friend self");
        }

        var Person = this.PersonFromCache(UserID);

        if (!Person) {
            return ErrorPromice("person not found");
        }
        //todo probally need to improve this method.
        try {
            var Result = this.generateRequest(UserID, Text);
        } catch (err) {
            console.error(err);
            return ErrorPromice(err);
        }
        var ID = UserID;
        return this.AjaxCall("/api/FreindRequest/", "POST", Result).then(  (response) => {
            this.RefreshPerson(ID);
            return response;
        });
    };



    AcceptSentFriendRequest(UserID) {
        var Person = this.PersonFromCache(UserID);
        if (!Person) {
            return ErrorPromice("Request not found");
        }

        if (!Secret) {
            return ErrorPromice("Invalid Secret");
        }
        return this.AcceptFriendRequest(UserID, Secret, True);
    };



    //Should only be called automcallty with Secret set
    AcceptFriendRequest(UserID, Secret, Automatic) {
        //todo should i use a Multi-Party Fair Exchange protocol here https://eprint.iacr.org/2015/064.pdf
        //todo i should add something to allow better error checking if the intial accept request fails
        var Person = this.PersonFromCache(UserID);

        if (Automatic && !Secret) {
            //todo check Secret
        }

        if (!Person || !Person.FriendRequest) {
            return ErrorPromice("Request not found");
        }

        var deferred = $.Deferred();
        var Message = null;
        if (!Person.AcceptedRequest && !Automatic) {
            try {
                Message = this.generateRequest(UserID);
            } catch (err) {
                console.error(err);
                deferred.reject(err);
                return;
            }
        } else if (Person.AcceptedRequest) {
            Message = {
                AcceptedOnly: true,
                OtherID: UserID,
                Message: Message
            };
        } else {
            console.log("invalid request state");
        }

        this.AjaxCall("/api/AcceptRequest/", "POST", Message).then(  (response) => {



            var Freind = this.RecieveRequest(response)
                .catch((err) => {
                    console.error(err);
                    deferred.reject(err);
                    return;
                })
                .then(() => {
                    this.RefreshPerson(Request.AccountID);
                    deferred.resolve(UserID);
                });
        })
            .catch((err) => {
                deferred.reject(err);
            });
        return deferred.promise();
    };



    SetProfilePic(PostID) {

        PostID = parseInt(PostID);
        if (!(PostID > 0)) {
            return ErrorPromice("invalid PostID");
        }

        return this.AjaxCall("/api/setprofile", "POST").then(  {
            ObjectID: PostID
        }, (response) => {

            this.RefreshPerson(this.AccountInfo.AccountID);
        });
    };


    GetStatus() {
        return this.AjaxCall("/api/status", "GET", null).then(  (response) => {

            try {
                if (!response) {
                    Zero.alert("invalid status");
                    return;
                }

                response = response[0];
            } catch (err) {
                Zero.alert("invalid status:" + err);
                return;
            }
            if (response.AcceptedRequests > 0) {
                this.AcceptAllAccepted();
            }

            return response;
        });

    };

    AcceptAllAccepted() {

        var deferred = $.Deferred();

        this.AjaxCall("/api/Accepted", "GET", null).then(  (response) => {

            if (!response) {
                deferred.reject("invalid responce");
                return;
            }

            response.forEach((item, index) => {
                this.RecieveRequest(item)
                    .then(() => {

                    })
                    .catch(() => {
                        this.Alert("failed to add freind");
                    });
            });
        });
        return deferred;
    };




    PostVote(PostID, Vote, CallBack, ErrorCallback) {


    };

    RefreshPerson(AccountID) {
        if (!AccountID) return;
        this.RemovePerson(AccountID);
        return this.PreloadPerson(AccountID)
            .then(() => {
                if (this.RefreshUserPage) this.RefreshUserPage(AccountID);
            });
    };




    RemovePerson(AccountID) {
        this.PeopleCashe[parseInt(AccountID)] = null;
    };

    PersonFromCache(AccountID) {
        var Result = this.PeopleCashe[parseInt(AccountID)];
        if (!Result) {
            return null;
        }
        if (Result.promise) { //Check if Differed
            return null;
        }
        return Result;
    };

    ContentPublicKeyFromCache(AccountID) {
        if (AccountID === this.AccountInfo.AccountID) {
            return this.Cryptostate.ContentPublicKey;
        }
        var Person = this.PersonFromCache(AccountID);
        if (!Person) {
            console.log("ContentPublicKey Person not found:" + AccountID);
            return null;
        }
        if (Person.ContentKey) return Person.ContentKey;
        return null;
    };


    PublicKeyFromCache(AccountID) {
        if (AccountID === this.AccountInfo.AccountID) {
            return this.Cryptostate.PublicPublicKey;
        }
        var Person = this.PersonFromCache(AccountID);
        if (!Person) {
            return null;
        }
        if (Person.PublicKey) return Person.PublicKey;
        return null;
    };


}




/**
 * Returns a Failed promise
 * @param {string} Message The ERROR MESSAGE of the promise
 * @returns {promise} a Failed promise
 */
function ErrorPromice(Message) {
    Promise.reject(Message);
}

/**
 * Returns a Finished promise
 * @param {object} Message The result of the promise
 * @returns {promise} a Finished promise
 */
function FinishedPromice(Message) {
    return Promise.resolve(Message);
}


function isArrayEmpty(array) {
    if (!array) return true;
    return !Array.isArray(array) || !array.length;
}


/**
 * Helper to get Cookie by name
 * @param {string} name  Cookie name
 * @returns {string} Cookie infomation
 */
function getCookie(name) {
    try {
        var value = "; " + document.cookie;
        var parts = value.split("; " + name + "=");
        if (parts.length === 2) return parts.pop()
            .split(";")
            .shift();
    } catch (err) {
        console.log(err);
        return null;
    }
    return null;
}

