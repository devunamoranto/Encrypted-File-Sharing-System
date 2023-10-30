package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

const BLOCK_SIZE = 128
const SIXTEEN_BYTES = 16
const DERIVED_KEY_SIZE = 64

type Signed interface {
	PreCheckMarshal() ([]byte, error)
}

// Public information on each user.
type Credentials struct {
	Username string
	Password []byte

	// UUIDS
	InvitationPK uuid.UUID
	FileSharePK  uuid.UUID
	SignaturePK  uuid.UUID
	UserStruct   uuid.UUID

	// IVs
	PasswordSalt []byte

	// Secret Keys
	InvitationSK []byte
	FileShareSK  []byte
	SignatureSK  []byte

	// Security
	Signature []byte
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	// Important info
	Username string

	// Security
	Pbk       []byte
	Signature []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileDesc struct {
	// Identifiers
	Identifier []byte
	Parent     string
	Children   []string

	// Access File Contents
	FileLocation uuid.UUID
	Signature    []byte
}

type File struct {
	// File Contents
	FirstBlock uuid.UUID
	LastBlock  uuid.UUID

	// Security
	Owner            string
	AuthorizedAccess []SharedFileAccess
	Integrity        []byte // Note: Done with hashing, not RSA
}

type Block struct {
	Content   []byte
	PrevBlock uuid.UUID
	NextBlock uuid.UUID
	Integrity []byte // Note: Done with hashing, not RSA

}

type SharedFileAccess struct {
	// Who can use these keys
	Username string
	Children []string

	// Security
	DecryptionKey []byte
	MacKey        []byte
	Signature     []byte
	SignedBy      string
}

type Invitation struct {
	EncKey    []byte
	Payload   []byte
	Signature []byte
}

type InvitationPayload struct {
	Parent       string
	Child        string
	FileLocation uuid.UUID
	SymKey       []byte
	MacKey       []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check if username exists
	if len(username) == 0 {
		return nil, fmt.Errorf("username cannot be empty")
	}
	entryExists, err := RetrieveCredEntry(username)
	if err != nil {
		return nil, err
	}
	if entryExists != nil {
		return nil, fmt.Errorf("user with name %v already exists", username)
	}

	// Compute on the fly values
	var credentials Credentials
	credentialsPtr := &credentials

	// Generate nonces
	passwordSalt := userlib.RandomBytes(SIXTEEN_BYTES)
	invitationIV := userlib.RandomBytes(SIXTEEN_BYTES)
	fileShareIV := userlib.RandomBytes(SIXTEEN_BYTES)
	signatureIV := userlib.RandomBytes(SIXTEEN_BYTES)
	userStructIV := userlib.RandomBytes(SIXTEEN_BYTES)

	// Generate keys
	pbk := userlib.Argon2Key([]byte(password), passwordSalt, SIXTEEN_BYTES)
	invitationPK, invitationSK, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	fileSharePK, fileShareSK, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	signatureSK, signaturePK, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Marshal generated keys
	marshInvitationSK, err := json.Marshal(invitationSK)
	if err != nil {
		return nil, err
	}
	marshFileShareSK, err := json.Marshal(fileShareSK)
	if err != nil {
		return nil, err
	}
	marshSignatureSK, err := json.Marshal(signatureSK)
	if err != nil {
		return nil, err
	}

	// Store RSA keys in keystore
	invitationUUID, err := KeystoreSetHelper(invitationPK)
	if err != nil {
		return nil, err
	}
	fileShareUUID, err := KeystoreSetHelper(fileSharePK)
	if err != nil {
		return nil, err
	}
	signatureUUID, err := KeystoreSetHelper(signaturePK)
	if err != nil {
		return nil, err
	}

	// Derive deterministic keys
	derivedKeyBook, _, err := DeriveKeys(pbk, nil)
	if err != nil {
		return nil, err
	}

	// Encrypt generated keys
	encInvitationSK := userlib.SymEnc(derivedKeyBook.symEncKey, invitationIV, marshInvitationSK)
	encFileShareSK := userlib.SymEnc(derivedKeyBook.symEncKey, fileShareIV, marshFileShareSK)
	encSignatureSK := userlib.SymEnc(derivedKeyBook.symEncKey, signatureIV, marshSignatureSK)

	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Pbk = pbk

	// Sign the user struct
	err = userdataptr.Sign(signatureSK)
	if err != nil {
		return nil, err
	}

	// Encrypt and store the user struct
	marshaledUser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	encryptedUser := userlib.SymEnc(derivedKeyBook.symEncKey, userStructIV, marshaledUser)
	userUUID, err := DatastoreSetHelper(encryptedUser)
	if err != nil {
		return nil, err
	}

	// Hash computation
	passwordHash := userlib.Hash(pbk)

	// Populate credentials
	credentials.Username = username
	credentials.Password = passwordHash

	credentials.InvitationPK = *invitationUUID
	credentials.FileSharePK = *fileShareUUID
	credentials.SignaturePK = *signatureUUID
	credentials.UserStruct = *userUUID

	credentials.PasswordSalt = passwordSalt

	credentials.InvitationSK = encInvitationSK
	credentials.FileShareSK = encFileShareSK
	credentials.SignatureSK = encSignatureSK

	err = credentialsPtr.Sign(signatureSK)
	if err != nil {
		return nil, err
	}
	//userlib.DebugMsg("Signed on creds: %v", credentialsPtr.Signature[:4])
	// Store credentials in datastore under key Credentials/Username
	err = credentialsPtr.StoreCredEntry()
	if err != nil {
		return nil, err
	}
	//userlib.DebugMsg("Credentials generated: %v", credentials.Username)

	// Return user data
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//userlib.DebugMsg("Logging in as %v with password %v", username, password)
	// Retrieve user from datastore
	credentials, err := RetrieveCredEntry(username)
	if err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, fmt.Errorf("there was no user with username %v", username)
	}

	// Check the provided credentials
	pbk := userlib.Argon2Key([]byte(password), credentials.PasswordSalt, SIXTEEN_BYTES)
	correctPassword := userlib.HMACEqual(userlib.Hash(pbk), credentials.Password)
	if !correctPassword {
		return nil, fmt.Errorf("incorrect password")
	}

	//userlib.DebugMsg("Credentials retrieved: %v", credentials.Username)

	// Derive deterministic keys
	derivedKeyBook, _, err := DeriveKeys(pbk, credentials)
	if err != nil {
		return nil, err
	}

	var userdata User
	userdataptr = &userdata
	// Retrieve the User struct from Datastore
	encryptedUser, ok := userlib.DatastoreGet(credentials.UserStruct)
	if !ok {
		return nil, fmt.Errorf("User struct not found")
	}
	if encryptedUser == nil {
		return nil, fmt.Errorf("User struct tampered with")
	}

	// Decrypt the user struct
	decryptedUser := userlib.SymDec(derivedKeyBook.symEncKey, encryptedUser)
	err = json.Unmarshal(decryptedUser, userdataptr)
	if err != nil {
		return nil, err
	}

	// Verify the integrity of the user struct
	err = CheckSignature(userdata.Signature, credentials.SignaturePK, userdataptr)
	if err != nil {
		return nil, err
	}

	//userlib.DebugMsg("User retrieved: %v", userdata.Username)

	return userdataptr, nil
}

// User struct Helpers
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Get credentials
	credentials, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return err
	}
	if credentials == nil {
		return fmt.Errorf("creds not found")
	}

	// Derive keys
	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, credentials)
	if err != nil {
		return err
	}

	// Generate file identifier (TODO: HANDLE THE CASE WHERE ID ALREADY EXISTS (OVERWRITE))
	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	if err != nil {
		return err
	}

	existingFileDesc, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, credentials.SignaturePK)
	if err != nil {
		return err
	}
	if existingFileDesc != nil {
		// Retrieve existing file
		file, symKey, macKey, err := existingFileDesc.RetrieveFileAndKeys(userdata, credentials, derivedKeyBook, skBook)
		if err != nil {
			return err
		}

		// Update existing file
		file.FirstBlock, file.LastBlock, err = StoreContent(symKey, macKey, content)
		if err != nil {
			return err
		}
		file.Integrity, err = file.ComputeIntegrity(macKey)
		if err != nil {
			return err
		}

		// Store in datastore
		marshaledFile, err := json.Marshal(file)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(existingFileDesc.FileLocation, marshaledFile)
		return nil
	}

	// Generate Encryption and HMAC keys for the file content
	fileEncKey := userlib.RandomBytes(SIXTEEN_BYTES)
	fileHmacKey := userlib.RandomBytes(SIXTEEN_BYTES)

	// Create a File struct
	var file File
	filePtr := &file

	file.FirstBlock, file.LastBlock, err = StoreContent(fileEncKey, fileHmacKey, content)
	if err != nil {
		return err
	}
	file.AuthorizedAccess = []SharedFileAccess{}
	file.Owner = userdata.Username

	err = filePtr.AddAuthorizedUser(userdata, userdata.Username, fileEncKey, fileHmacKey, "")
	if err != nil {
		return err
	}
	file.Integrity, err = filePtr.ComputeIntegrity(fileHmacKey)
	if err != nil {
		return err
	}

	// Store the file struct in datastore
	marshaledFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	fileLocation := DatastoreRandomSetHelper(marshaledFile)

	// Create file descriptor
	var fd FileDesc
	fdptr := &fd

	fd.Identifier = fileIdentifier
	fd.Parent = ""
	fd.Children = []string{}
	fd.FileLocation = *fileLocation
	//userlib.DebugMsg("(StoreFile) ID: %v, Location: %v, FirstBlock: %v, LastBlock: %v", fd.Identifier[:8], fd.FileLocation, file.FirstBlock, file.LastBlock)
	// Sign the file descriptor
	signatureSK := skBook.signatureSK
	err = fdptr.Sign(signatureSK)
	if err != nil {
		return err
	}
	//userlib.DebugMsg("Signed on filedesc: %v", fdptr.Signature[:4])

	// Store file descriptor in datastore
	marshaledFd, err := json.Marshal(fd)
	if err != nil {
		return err
	}
	encFd := userlib.SymEnc(derivedKeyBook.symEncKey, userlib.RandomBytes(SIXTEEN_BYTES), marshaledFd)
	storageID, err := UUIDFromFileID(fileIdentifier, derivedKeyBook.hmacKey)
	//userlib.DebugMsg("UUID: %v, with entries %v and %v", storageID, fileIdentifier, derivedKeyBook.symEncKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageID, encFd)

	/*
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return err
		}
		contentBytes, err := json.Marshal(content)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, contentBytes)
	*/
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	creds, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return err
	}
	if creds == nil {
		return fmt.Errorf("there was no user with username %v", userdata.Username)
	}

	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, creds)
	if err != nil {
		return err
	}
	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	if err != nil {
		return err
	}
	fdptr, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, creds.SignaturePK)
	if err != nil {
		return err
	}
	if fdptr == nil {
		return fmt.Errorf("not authorized to append to this file")
	}

	return fdptr.AppendToFile(content, userdata, creds, derivedKeyBook, skBook)
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Retrieve file descriptor
	credentials, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, fmt.Errorf("there was no user with username %v", userdata.Username)
	}

	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, credentials)
	if err != nil {
		return nil, err
	}

	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	if err != nil {
		return nil, err
	}
	fileDescPtr, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, credentials.SignaturePK)
	if err != nil {
		return nil, err
	}
	if fileDescPtr == nil {
		return nil, fmt.Errorf("File does not exist in the space of %v", userdata.Username)
	}

	// Retrieve file struct
	file, symKey, macKey, err := fileDescPtr.RetrieveFileAndKeys(userdata, credentials, derivedKeyBook, skBook)
	if err != nil {
		return nil, err
	}

	content, err = file.ReassembleContent(symKey, macKey)
	return content, err

	/*
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return nil, err
		}
		dataJSON, ok := userlib.DatastoreGet(storageKey)
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found"))
		}
		err = json.Unmarshal(dataJSON, &content)
		return content, err
	*/
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//userlib.DebugMsg("Inviting %v to edit %v", recipientUsername, filename)
	creds, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	if creds == nil {
		return uuid.Nil, fmt.Errorf("there was no user with username %v", userdata.Username)
	}
	invitedCreds, err := RetrieveCredEntry(recipientUsername)
	if err != nil {
		return uuid.Nil, err
	}
	if invitedCreds == nil {
		return uuid.Nil, fmt.Errorf("this user does not exist")
	}

	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, creds)
	if err != nil {
		return uuid.Nil, err
	}

	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	//userlib.DebugMsg("Identifier: %v", fileIdentifier[:8])
	if err != nil {
		return uuid.Nil, err
	}
	fdptr, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, creds.SignaturePK)
	if err != nil {
		return uuid.Nil, err
	}
	if fdptr == nil {
		return uuid.Nil, fmt.Errorf("file not existing")
	}

	// Obtain keys for the file
	file, symKey, macKey, err := fdptr.RetrieveFileAndKeys(userdata, creds, derivedKeyBook, skBook)
	if err != nil {
		return uuid.Nil, err
	}

	// Create invitation with this file
	var invite InvitationPayload
	invite.Parent = userdata.Username
	invite.Child = recipientUsername
	invite.FileLocation = fdptr.FileLocation
	invite.SymKey = symKey
	invite.MacKey = macKey

	// Encrypt invitation payload with random symmetric key
	randKey := userlib.RandomBytes(SIXTEEN_BYTES)
	iv := userlib.RandomBytes(SIXTEEN_BYTES)
	marshaledInvite, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, err
	}
	encInvite := userlib.SymEnc(randKey, iv, marshaledInvite)

	// Create an Invitation struct and hybrid encrypt the key
	var inviteCasing Invitation

	inviteeInvitationPK, err := KeystoreGetHelper(invitedCreds.InvitationPK)
	if err != nil {
		return uuid.Nil, err
	}
	encKey, err := userlib.PKEEnc(*inviteeInvitationPK, randKey)
	if err != nil {
		return uuid.Nil, err
	}

	inviteCasing.EncKey = encKey
	inviteCasing.Payload = encInvite

	// Sign off on invitation
	signatureSK := skBook.signatureSK
	if err != nil {
		return uuid.Nil, err
	}
	err = inviteCasing.Sign(signatureSK)
	if err != nil {
		return uuid.Nil, err
	}

	// Marshal and store the invitation
	marshaledPackage, err := json.Marshal(inviteCasing)
	if err != nil {
		return uuid.Nil, err
	}

	storageID := DatastoreRandomSetHelper(marshaledPackage)
	// Add invitee to list of children
	fdptr.Children = append(fdptr.Children, recipientUsername)

	sharedAccess, index, err := file.FindAuthorizedUser(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}

	sharedAccess.SignedBy = userdata.Username
	sharedAccess.Children = append(sharedAccess.Children, recipientUsername)
	err = sharedAccess.Sign(skBook.signatureSK)
	if err != nil {
		return uuid.Nil, err
	}
	file.AuthorizedAccess[index] = *sharedAccess
	file.Integrity, err = file.ComputeIntegrity(macKey)
	if err != nil {
		return uuid.Nil, err
	}
	marshaledFile, err := json.Marshal(*file)
	if err != nil {
		return uuid.Nil, err
	}

	err = fdptr.Sign(signatureSK)
	if err != nil {
		return uuid.Nil, err
	}

	// Update fd in datastore
	marshaledFd, err := json.Marshal(*fdptr)
	if err != nil {
		return uuid.Nil, err
	}

	fdUUID, err := UUIDFromFileID(fileIdentifier, derivedKeyBook.hmacKey)
	if err != nil {
		return uuid.Nil, err
	}
	encFd := userlib.SymEnc(derivedKeyBook.symEncKey, userlib.RandomBytes(SIXTEEN_BYTES), marshaledFd)

	userlib.DatastoreSet(fdptr.FileLocation, marshaledFile)
	userlib.DatastoreSet(fdUUID, encFd)
	return *storageID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//userlib.DebugMsg("Accepting invite from %v", senderUsername)
	// Preamble stuff
	senderCreds, err := RetrieveCredEntry(senderUsername)
	if err != nil {
		return err
	}
	if senderCreds == nil {
		return fmt.Errorf("there was no user with username %v", senderUsername)
	}
	creds, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return err
	}
	if creds == nil {
		return fmt.Errorf("there was no user with username %v", userdata.Username)
	}
	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, creds)
	if err != nil {
		return err
	}
	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	if err != nil {
		return err
	}

	// Check that file doesn't already exist
	existingFd, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, creds.SignaturePK)
	if err != nil {
		return err
	}
	if existingFd != nil {
		return fmt.Errorf("file already exists for user %v", userdata.Username)
	}

	invitationSK := skBook.invitationSK

	// Open invite
	var inviteCasing Invitation
	marshaledPackage, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return fmt.Errorf("no invite found")
	}
	if marshaledPackage == nil {
		return fmt.Errorf("invite has disappeared")
	}
	err = json.Unmarshal(marshaledPackage, &inviteCasing)
	if err != nil {
		return err
	}

	// Validate invite and open the payload
	err = CheckSignature(inviteCasing.Signature, senderCreds.SignaturePK, &inviteCasing)
	if err != nil {
		return err
	}

	decKey, err := userlib.PKEDec(invitationSK, inviteCasing.EncKey)
	if err != nil {
		return err
	}

	var invite InvitationPayload
	decInvite := userlib.SymDec(decKey, inviteCasing.Payload)
	err = json.Unmarshal(decInvite, &invite)
	if err != nil {
		return err
	}

	// Check that the invite really came from this user
	if invite.Parent != senderUsername {
		return fmt.Errorf("senderUsername does not match the sender in the invite")
	}

	// Create a new file descriptor
	var fd FileDesc

	fd.Identifier = fileIdentifier
	fd.Parent = invite.Parent
	fd.Children = []string{}
	fd.FileLocation = invite.FileLocation

	// Sign it
	err = fd.Sign(skBook.signatureSK)
	if err != nil {
		return err
	}

	// Retrieve file struct from datastore
	var file File
	marshaledFile, ok := userlib.DatastoreGet(fd.FileLocation)
	if !ok {
		return fmt.Errorf("no file found")
	}
	if marshaledFile == nil {
		return fmt.Errorf("file struct is gone")
	}
	err = json.Unmarshal(marshaledFile, &file)
	if err != nil {
		return err
	}

	err = invite.AcceptHelper(userdata, &file, invite.Parent)
	if err != nil {
		return err
	}

	// Store FD in datastore
	marshaledFd, err := json.Marshal(fd)
	if err != nil {
		return err
	}
	encFd := userlib.SymEnc(derivedKeyBook.symEncKey, userlib.RandomBytes(SIXTEEN_BYTES), marshaledFd)
	storageId, err := UUIDFromFileID(fileIdentifier, derivedKeyBook.hmacKey)
	if err != nil {
		return err
	}
	//userlib.DebugMsg("(AcceptInvite) Username: %v FileDesc Location: %v", invite.Child, storageId)
	userlib.DatastoreSet(storageId, encFd)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	creds, err := RetrieveCredEntry(userdata.Username)
	if err != nil {
		return err
	}
	if creds == nil {
		return fmt.Errorf("there was no user with username %v", userdata.Username)
	}
	derivedKeyBook, skBook, err := DeriveKeys(userdata.Pbk, creds)
	if err != nil {
		return err
	}

	fileIdentifier, err := userdata.GenerateFileId(filename, derivedKeyBook.hmacKey)
	if err != nil {
		return nil
	}
	fdptr, err := userdata.FindFileById(fileIdentifier, derivedKeyBook, creds.SignaturePK)
	if err != nil {
		return err
	}
	if fdptr == nil {
		return fmt.Errorf("file nonexistent here")
	}

	// Retrieve file struct
	file, symKey, macKey, err := fdptr.RetrieveFileAndKeys(userdata, creds, derivedKeyBook, skBook)
	if err != nil {
		return err
	}

	accessToRevoke, _, err := file.FindAuthorizedUser(recipientUsername)
	if err != nil {
		return err
	}
	if accessToRevoke == nil {
		return fmt.Errorf("file not shared with this user")
	}

	// Remove users recursively
	_, err = file.NamesToRevoke(recipientUsername)
	if err != nil {
		return err
	}
	//userlib.DebugMsg("Revocation of %v removes %v", recipientUsername, namesToRevoke)

	// Check that the contents are still ok
	content, err := file.ReassembleContent(symKey, macKey)
	if err != nil {
		return nil
	}

	// Generate new keys and re-store contents
	newSymKey := userlib.RandomBytes(SIXTEEN_BYTES)
	newMacKey := userlib.RandomBytes(SIXTEEN_BYTES)
	file.FirstBlock, file.LastBlock, err = StoreContent(newSymKey, newMacKey, content)
	if err != nil {
		return err
	}

	// Update keys for okay users
	err = file.UpdateKeys(userdata, newSymKey, newMacKey, skBook.signatureSK)
	if err != nil {
		return err
	}

	// Update the file struct
	file.Integrity, err = file.ComputeIntegrity(newMacKey)
	if err != nil {
		return err
	}

	// Store file in datastore
	marshaledFile, err := json.Marshal(*file)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fdptr.FileLocation, marshaledFile)

	return nil
}

// Create a random UUID for a key, and put it in keystore. Return the UUID
func KeystoreSetHelper(value userlib.PublicKeyType) (*uuid.UUID, error) {
	generatedUUID := uuid.New()
	err := userlib.KeystoreSet(generatedUUID.String(), value)
	if err != nil {
		return nil, err
	}
	return &generatedUUID, nil
}

func KeystoreGetHelper(key uuid.UUID) (*userlib.PublicKeyType, error) {
	storedKey, ok := userlib.KeystoreGet(key.String())
	if !ok {
		return nil, fmt.Errorf("the desired public key was not found in Keystore")
	}
	return &storedKey, nil
}

// Helper function for deterministic datastore set
func DatastoreSetHelper(value []byte) (*uuid.UUID, error) {
	hash := userlib.Hash(value)
	generatedUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(generatedUUID, value)
	return &generatedUUID, nil
}

func DatastoreRandomSetHelper(value []byte) *uuid.UUID {
	generatedUUID := uuid.New()
	userlib.DatastoreSet(generatedUUID, value)
	return &generatedUUID
}

// Bookkeeping for derived keys
type DerivedKeyBook struct {
	symEncKey []byte
	hmacKey   []byte
}

// Key Derivation
func DeriveKeys(pbk []byte, creds *Credentials) (*DerivedKeyBook, *SecretKeyBook, error) {
	var derivedKeys DerivedKeyBook
	var err error = nil

	// Key for symmetric encryption
	symEnc, err := userlib.HashKDF(pbk, []byte("symmetric encryption key"))
	if err != nil {
		return nil, nil, err
	}
	derivedKeys.symEncKey = symEnc[:16]

	// Key for HMAC
	hmac, err := userlib.HashKDF(pbk, []byte("hmac key"))
	if err != nil {
		return nil, nil, err
	}
	derivedKeys.hmacKey = hmac[:16]

	if creds != nil {
		skBook, err := DecryptSecretKeys(creds, &derivedKeys)
		if err != nil {
			return nil, nil, err
		}
		return &derivedKeys, skBook, nil
	}

	return &derivedKeys, nil, err
}

type SecretKeyBook struct {
	invitationSK userlib.PKEDecKey
	fileShareSK  userlib.PKEDecKey
	signatureSK  userlib.DSSignKey
}

func DecryptSecretKeys(creds *Credentials, derivedKeyBook *DerivedKeyBook) (*SecretKeyBook, error) {
	encInvitationSK := creds.InvitationSK
	decInvitationSK := userlib.SymDec(derivedKeyBook.symEncKey, encInvitationSK)
	var invitationSK userlib.PKEDecKey
	err := json.Unmarshal(decInvitationSK, &invitationSK)
	if err != nil {
		return nil, err
	}

	encSignatureSK := creds.SignatureSK
	decSignatureSK := userlib.SymDec(derivedKeyBook.symEncKey, encSignatureSK)
	var signatureSK userlib.PKEDecKey
	err = json.Unmarshal(decSignatureSK, &signatureSK)
	if err != nil {
		return nil, err
	}

	encFileShareSK := creds.FileShareSK
	decFileShareSK := userlib.SymDec(derivedKeyBook.symEncKey, encFileShareSK)
	var fileShareSK userlib.PKEDecKey
	err = json.Unmarshal(decFileShareSK, &fileShareSK)
	if err != nil {
		return nil, err
	}

	var skBook SecretKeyBook
	skBook.invitationSK = invitationSK
	skBook.fileShareSK = fileShareSK
	skBook.signatureSK = signatureSK

	return &skBook, nil
}

// Store a marshaled credentials entry
func (creds *Credentials) StoreCredEntry() error {
	marshaledCreds, err := json.Marshal(*creds)
	if err != nil {
		return err
	}
	datastoreKey := "Credentials/" + creds.Username
	hash := userlib.Hash([]byte(datastoreKey))
	generatedUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(generatedUUID, marshaledCreds)
	return nil
}

// Get a credentials entry and unmarshal it, if it exists
func RetrieveCredEntry(username string) (*Credentials, error) {
	// Get the credentials
	var creds Credentials
	credsPtr := &creds

	datastoreKey := "Credentials/" + username
	hash := userlib.Hash([]byte(datastoreKey))
	generatedUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	value, ok := userlib.DatastoreGet(generatedUUID)
	if !ok {
		return nil, nil
	}
	if value == nil {
		return nil, nil
	}
	err = json.Unmarshal(value, credsPtr)
	if err != nil {
		return nil, err
	}

	// Verify the credentials
	err = CheckSignature(creds.Signature, creds.SignaturePK, credsPtr)
	if err != nil {
		return nil, err
	}

	return credsPtr, nil
}

// Generate a file identifier from a filename for a user
func (user *User) GenerateFileId(filename string, key []byte) ([]byte, error) {
	hashedId, err := userlib.HMACEval(key, []byte(user.Username+filename))
	if err != nil {
		return nil, err
	}
	return hashedId, nil
}

func UUIDFromFileID(fileIdentifier []byte, key []byte) (uuid.UUID, error) {
	concat := append(fileIdentifier, []byte("FileDesc Storage")...)
	hash, err := userlib.HMACEval(key, concat)
	if err != nil {
		return uuid.Nil, err
	}
	genUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return uuid.Nil, err
	}
	return genUUID, nil
}

func (user *User) FindFileById(id []byte, derivedKeyBook *DerivedKeyBook, signaturePK uuid.UUID) (*FileDesc, error) {

	var fileDesc FileDesc
	uuidToFind, err := UUIDFromFileID(id, derivedKeyBook.hmacKey)

	if err != nil {
		return nil, err
	}
	//userlib.DebugMsg("(FindFileById): FileDesc Location: %v, FileDesc ID: %v", uuidToFind, id[:8])

	encFd, ok := userlib.DatastoreGet(uuidToFind)
	if (!ok) || encFd == nil {
		return nil, nil
	}

	//userlib.DebugMsg("(FindFileById): Enc FD: %v", encFd[:8])
	marshaledFd := userlib.SymDec(derivedKeyBook.symEncKey, encFd)
	err = json.Unmarshal(marshaledFd, &fileDesc)
	if err != nil {
		return nil, err
	}
	//userlib.DebugMsg("(FindFileById) FileDesc ID: %v, FileLocation: %v", id[:8], fileDesc.FileLocation)
	err = CheckSignature(fileDesc.Signature, signaturePK, &fileDesc)
	if err != nil {
		return nil, err
	}

	return &fileDesc, nil
}

// thanks for not importing bytes package
func EqualBytes(a []byte, b []byte) bool {
	return string(a) == string(b)
}

/*
 * The following section handles signatures and signature checking
 */

// #region Signatures
func (creds *Credentials) Sign(signatureKey userlib.DSSignKey) error {
	credBytes, err := creds.PreCheckMarshal()
	if err != nil {
		return err
	}

	hash := userlib.Hash(credBytes)

	signature, err := userlib.DSSign(signatureKey, hash)
	if err != nil {
		return err
	}

	creds.Signature = signature
	return nil
}

func (user *User) Sign(signatureKey userlib.DSSignKey) error {
	userBytes, err := user.PreCheckMarshal()
	if err != nil {
		return err
	}

	hash := userlib.Hash(userBytes)

	signature, err := userlib.DSSign(signatureKey, hash)
	if err != nil {
		return err
	}

	user.Signature = signature
	return nil
}

func (fd *FileDesc) Sign(signatureKey userlib.DSSignKey) error {
	fdBytes, err := fd.PreCheckMarshal()
	if err != nil {
		return err
	}

	hash := userlib.Hash(fdBytes)

	signature, err := userlib.DSSign(signatureKey, hash)
	if err != nil {
		return err
	}

	fd.Signature = signature
	return nil
}

func (sharedAccess *SharedFileAccess) Sign(signatureKey userlib.DSSignKey) error {
	sharedBytes, err := sharedAccess.PreCheckMarshal()
	if err != nil {
		return err
	}

	hash := userlib.Hash(sharedBytes)

	signature, err := userlib.DSSign(signatureKey, hash)
	if err != nil {
		return err
	}

	sharedAccess.Signature = signature
	return nil
}

func (invite *Invitation) Sign(signatureKey userlib.DSSignKey) error {
	inviteBytes, err := invite.PreCheckMarshal()
	if err != nil {
		return err
	}

	hash := userlib.Hash(inviteBytes)

	signature, err := userlib.DSSign(signatureKey, hash)
	if err != nil {
		return err
	}

	invite.Signature = signature
	return nil
}

// Check Signatures
func CheckSignature(signature []byte, signaturePKUUID uuid.UUID, signed Signed) error {
	marshaledBytes, err := signed.PreCheckMarshal()
	if err != nil {
		return err
	}

	signaturePK, ok := userlib.KeystoreGet(signaturePKUUID.String())
	if !ok {
		return fmt.Errorf("there was no valid DSVerifyKey found associated with this struct")
	}

	hash := userlib.Hash(marshaledBytes)
	//userlib.DebugMsg("(CheckSig) Hash: %v, Sig: %v", hash[:4], signature[:4])
	err = userlib.DSVerify(signaturePK, hash, signature)
	if err != nil {
		return err
	}
	return nil
}

// #endregion Signatures

/*
 * The following functions marshal a struct without its signature field
 */

// #region PreCheckMarshal
func (cred *Credentials) PreCheckMarshal() ([]byte, error) {
	tempSig := cred.Signature
	cred.Signature = nil
	marshaled, err := json.Marshal(*cred)
	cred.Signature = tempSig
	if err != nil {
		return nil, err
	}
	return marshaled, nil
}

func (user *User) PreCheckMarshal() ([]byte, error) {
	tempSig := user.Signature
	user.Signature = nil
	marshaled, err := json.Marshal(*user)
	user.Signature = tempSig
	if err != nil {
		return nil, err
	}
	return marshaled, nil
}

func (fd *FileDesc) PreCheckMarshal() ([]byte, error) {
	tempSig := fd.Signature
	fd.Signature = nil
	marshaled, err := json.Marshal(*fd)
	fd.Signature = tempSig
	if err != nil {
		return nil, err
	}
	return marshaled, nil
}

func (sharedAccess *SharedFileAccess) PreCheckMarshal() ([]byte, error) {
	tempSig := sharedAccess.Signature
	sharedAccess.Signature = nil
	marshaled, err := json.Marshal(*sharedAccess)
	sharedAccess.Signature = tempSig
	if err != nil {
		return nil, err
	}
	return marshaled, nil
}

func (invite *Invitation) PreCheckMarshal() ([]byte, error) {
	tempSig := invite.Signature
	invite.Signature = nil
	marshaled, err := json.Marshal(*invite)
	invite.Signature = tempSig
	if err != nil {
		return nil, err
	}
	return marshaled, nil
}

// #endregion PreCheckMarshal

/*
 * The following section handles file storage and sharing
 */

// Stores file content in a block format. Returns the UUID of the first block and the last block.
func StoreContent(encKey []byte, hmacKey []byte, content []byte) (uuid.UUID, uuid.UUID, error) {
	totalBytes := len(content)
	var firstBlock Block
	firstBlock.PrevBlock = uuid.Nil
	curBlock := firstBlock
	var prevBlock Block
	var curBlockUUID uuid.UUID

	firstBlockUUID := uuid.Nil
	var lastBLockUUID uuid.UUID

	curBlockUUID = uuid.New()
	for i := 0; i < totalBytes || (totalBytes == 0 && i == 0); i += BLOCK_SIZE {
		// Initialize current block
		//userlib.DebugMsg("Storing bytes %v through %v of file size %v", i, i+BLOCK_SIZE, totalBytes)
		curBlockUUID = uuid.New()
		if i == 0 {
			firstBlockUUID = curBlockUUID
		}

		curBlock.NextBlock = uuid.Nil

		// Update previous block and store in Datastore
		if curBlock.PrevBlock != uuid.Nil {
			prevBlock.NextBlock = curBlockUUID

			// Security
			prevPtr := &prevBlock
			prevInteg, err := prevPtr.ComputeIntegrity(hmacKey)
			prevBlock.Integrity = prevInteg
			if err != nil {
				return uuid.Nil, uuid.Nil, err
			}

			marshaledBlock, err := json.Marshal(prevBlock)
			if err != nil {
				return uuid.Nil, uuid.Nil, err
			}
			userlib.DatastoreSet(curBlock.PrevBlock, marshaledBlock)
		}

		// Store encrypted content in current block
		iv := userlib.RandomBytes(SIXTEEN_BYTES)

		// Not Last block
		if i+BLOCK_SIZE < totalBytes {
			encContent := userlib.SymEnc(encKey, iv, content[i:i+BLOCK_SIZE])
			curBlock.Content = encContent
			var nextBlock Block
			nextBlock.PrevBlock = curBlockUUID
			prevBlock = curBlock
			curBlock = nextBlock
		} else {
			// Last block
			encContent := userlib.SymEnc(encKey, iv, content[i:])
			curBlock.Content = encContent
		}
	}

	if totalBytes == 0 {
		iv := userlib.RandomBytes(SIXTEEN_BYTES)
		encContent := userlib.SymEnc(encKey, iv, []byte{})
		curBlock.Content = encContent
	}

	// Handle last block
	curPtr := &curBlock
	curInteg, err := curPtr.ComputeIntegrity(hmacKey)
	curBlock.Integrity = curInteg
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	curBlock.NextBlock = uuid.Nil
	lastBLockUUID = curBlockUUID

	marshaledBlock, err := json.Marshal(curBlock)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	userlib.DatastoreSet(curBlockUUID, marshaledBlock)

	return firstBlockUUID, lastBLockUUID, nil
}

func (fdPtr *FileDesc) RetrieveFileAndKeys(userStruct *User, creds *Credentials, derivedKeyBook *DerivedKeyBook, skBook *SecretKeyBook) (*File, []byte, []byte, error) {
	var file File
	filePtr := &file
	marshaledFile, ok := userlib.DatastoreGet(fdPtr.FileLocation)
	if !ok || marshaledFile == nil {
		return nil, nil, nil, fmt.Errorf("no file found")
	}
	err := json.Unmarshal(marshaledFile, filePtr)
	if err != nil {
		return nil, nil, nil, err
	}

	// Get shared access for this file
	sharedAccessPtr, _, err := filePtr.FindAuthorizedUser(userStruct.Username)
	if err != nil {
		return nil, nil, nil, err
	}
	if sharedAccessPtr == nil {
		return nil, nil, nil, fmt.Errorf("not an authorized user")
	}

	// Check that the signing user is allowed to grant file sharing access
	if sharedAccessPtr.SignedBy != filePtr.Owner {
		signerSharedAccess, _, err := filePtr.FindAuthorizedUser(sharedAccessPtr.SignedBy)
		if err != nil {
			return nil, nil, nil, err
		}
		if signerSharedAccess == nil {
			return nil, nil, nil, fmt.Errorf("no authorized user entry found")
		}
	}

	// Check Signature on SharedAccess struct
	signerCreds, err := RetrieveCredEntry(sharedAccessPtr.SignedBy)
	if err != nil {
		return nil, nil, nil, err
	}
	if signerCreds == nil {
		return nil, nil, nil, fmt.Errorf("no creds")
	}

	//userlib.DebugMsg("File: %v, Signature: %v, SignedBy: %v Children: %v", sharedAccessPtr.Username, sharedAccessPtr.Signature[:4], sharedAccessPtr.SignedBy, sharedAccessPtr.Children)
	err = CheckSignature(sharedAccessPtr.Signature, signerCreds.SignaturePK, sharedAccessPtr)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive shared keys
	fileShareSK := skBook.fileShareSK
	symKey, err := userlib.PKEDec(fileShareSK, sharedAccessPtr.DecryptionKey)
	if err != nil {
		return nil, nil, nil, err
	}

	macKey, err := userlib.PKEDec(fileShareSK, sharedAccessPtr.MacKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Check integrity of file struct
	err = file.CheckIntegrity(macKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return filePtr, symKey, macKey, nil
}

func (fdptr *FileDesc) AppendToFile(content []byte, userStruct *User, creds *Credentials, derivedKeyBook *DerivedKeyBook, skBook *SecretKeyBook) error {
	totalBytes := len(content)
	filePtr, encKey, hmacKey, err := fdptr.RetrieveFileAndKeys(userStruct, creds, derivedKeyBook, skBook)
	if err != nil {
		return err
	}

	var curBlock Block
	var prevBlock Block
	prevPtr := &prevBlock
	var curBlockUUID uuid.UUID

	// Get last block
	marshaledBlock, ok := userlib.DatastoreGet(filePtr.LastBlock)
	if !ok || marshaledBlock == nil {
		return fmt.Errorf("no block struct found")
	}
	err = json.Unmarshal(marshaledBlock, &prevBlock)
	//userlib.DebugMsg("Last block was %v", filePtr.LastBlock)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no block found")
	}
	// Check integrity of block
	hash, err := prevPtr.ComputeIntegrity(hmacKey)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(hash, prevBlock.Integrity) {
		return fmt.Errorf("mismatching mac")
	}

	// Start current block pointing to last one
	curBlock.PrevBlock = filePtr.LastBlock

	for i := 0; i < totalBytes || (totalBytes == 0 && i == 0); i += BLOCK_SIZE {
		// Initialize current block
		//userlib.DebugMsg("Storing bytes %v through %v of file size %v", i, i+BLOCK_SIZE, totalBytes)
		curBlockUUID = uuid.New()

		curBlock.NextBlock = uuid.Nil

		// Update previous block and store in Datastore
		if curBlock.PrevBlock != uuid.Nil {
			prevBlock.NextBlock = curBlockUUID

			// Security
			prevPtr := &prevBlock
			prevInteg, err := prevPtr.ComputeIntegrity(hmacKey)
			prevBlock.Integrity = prevInteg
			if err != nil {
				return err
			}

			marshaledBlock, err := json.Marshal(prevBlock)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(curBlock.PrevBlock, marshaledBlock)
		}

		// Store encrypted content in current block
		iv := userlib.RandomBytes(SIXTEEN_BYTES)

		// Last block
		if i+BLOCK_SIZE < totalBytes {
			encContent := userlib.SymEnc(encKey, iv, content[i:i+BLOCK_SIZE])
			curBlock.Content = encContent

			var nextBlock Block
			nextBlock.PrevBlock = curBlockUUID
			prevBlock = curBlock
			curBlock = nextBlock
		} else {
			// Not last block
			encContent := userlib.SymEnc(encKey, iv, content[i:])
			curBlock.Content = encContent
			//userlib.DebugMsg("(Append) Block %v has content %v", curBlock, encContent)
		}
	}

	/*
		if totalBytes == 0 {
			iv := userlib.RandomBytes(SIXTEEN_BYTES)
			encContent := userlib.SymEnc(encKey, iv, []byte{})
			curBlock.Content = encContent
		}
	*/

	// Handle last block
	curPtr := &curBlock
	curInteg, err := curPtr.ComputeIntegrity(hmacKey)
	curBlock.Integrity = curInteg
	if err != nil {
		return err
	}

	curBlock.NextBlock = uuid.Nil

	marshaledBlock, err = json.Marshal(curBlock)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(curBlockUUID, marshaledBlock)

	// Update file struct
	//userlib.DebugMsg("Last block now %v", curBlockUUID)
	filePtr.LastBlock = curBlockUUID
	filePtr.Integrity, err = filePtr.ComputeIntegrity(hmacKey)
	if err != nil {
		return err
	}
	// Store file struct in datastore
	marshaledFile, err := json.Marshal(filePtr)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fdptr.FileLocation, marshaledFile)

	return nil
}

func (fileptr *File) ComputeIntegrity(hmacKey []byte) ([]byte, error) {
	tempHash := fileptr.Integrity
	fileptr.Integrity = nil
	marshaled, err := json.Marshal(*fileptr)
	fileptr.Integrity = tempHash
	if err != nil {
		return nil, err
	}

	// Hash contents and return hash
	hash, err := userlib.HMACEval(hmacKey, marshaled)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (block *Block) ComputeIntegrity(hmacKey []byte) ([]byte, error) {
	tempHash := block.Integrity
	block.Integrity = nil
	marshaled, err := json.Marshal(*block)
	block.Integrity = tempHash
	if err != nil {
		return nil, err
	}

	// Hash contents and return hash
	hash, err := userlib.HMACEval(hmacKey, marshaled)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (fileptr *File) CheckIntegrity(hmacKey []byte) error {
	//userlib.DebugMsg("firstBlock: %v, lastBLock: %v, integ: %v", fileptr.FirstBlock, fileptr.LastBlock, fileptr.Integrity)
	tempHash := fileptr.Integrity
	fileptr.Integrity = nil
	marshaled, err := json.Marshal(*fileptr)
	fileptr.Integrity = tempHash
	if err != nil {
		return err
	}

	// Check hash
	hash, err := userlib.HMACEval(hmacKey, marshaled)
	if err != nil {
		return err
	}
	equivalent := userlib.HMACEqual(hash, fileptr.Integrity)
	if !equivalent {
		return fmt.Errorf("corrupted File struct")
	}
	return nil
}

// Add to authorized users
func (invite *InvitationPayload) AcceptHelper(userdata *User, file *File, sender string) error {
	// Check that the signing user is allowed to grant file sharing access
	senderSharedAccess, _, err := file.FindAuthorizedUser(sender)
	if err != nil {
		return err
	}
	if senderSharedAccess == nil {
		return fmt.Errorf("no authorized user entry found")
	}

	err = file.AddAuthorizedUser(userdata, invite.Child, invite.SymKey, invite.MacKey, sender)
	if err != nil {
		return err
	}
	// Sign struct
	file.Integrity, err = file.ComputeIntegrity(invite.MacKey)
	if err != nil {
		return err
	}

	// Update file struct in datastore
	marshaledFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(invite.FileLocation, marshaledFile)

	return err
}

func (fileptr *File) AddAuthorizedUser(signingUser *User, username string, symKey []byte, macKey []byte, parent string) error {
	/*
		// Check that the signing user is allowed to grant file sharing access
		if signingUser.Username != fileptr.Owner {
			signerSharedAccess, err := fileptr.FindAuthorizedUser(signingUser.Username)
			if err != nil {
				return err
			}
			if signerSharedAccess == nil {
				return fmt.Errorf("No authorized user entry found")
			}
		}
	*/

	// Retrieve user credentials
	signerCreds, err := RetrieveCredEntry(username)
	if err != nil {
		return err
	}
	if signerCreds == nil {
		return fmt.Errorf("no valid credentials for signing user")
	}

	userCreds, err := RetrieveCredEntry(username)
	if err != nil {
		return err
	}
	if userCreds == nil {
		return fmt.Errorf("there was no user with username %v", username)
	}

	// Encrypt file keys with the new user's public key information
	fileSharePK, err := KeystoreGetHelper(userCreds.FileSharePK)
	if err != nil {
		return err
	}

	encSymKey, err := userlib.PKEEnc(*fileSharePK, symKey)
	if err != nil {
		return err
	}
	encMacKey, err := userlib.PKEEnc(*fileSharePK, macKey)
	if err != nil {
		return err
	}

	// Create SharedFileAccess
	var sharedAccess SharedFileAccess
	sharedAccess.Username = username
	sharedAccess.DecryptionKey = encSymKey
	sharedAccess.MacKey = encMacKey
	sharedAccess.SignedBy = signingUser.Username
	sharedAccess.Children = []string{}

	// Decrypt the signing user's SK
	_, skBook, err := DeriveKeys(signingUser.Pbk, signerCreds)
	if err != nil {
		return err
	}

	signatureSK := skBook.signatureSK

	// Sign off on the addition
	err = sharedAccess.Sign(signatureSK)
	if err != nil {
		return err
	}

	fileptr.AuthorizedAccess = append(fileptr.AuthorizedAccess, sharedAccess)
	//userlib.DebugMsg("Authorized user added: %v", fileptr.AuthorizedAccess[len(fileptr.AuthorizedAccess)-1].Username)
	return nil
}

func (fileptr *File) ReassembleContent(symKey []byte, macKey []byte) ([]byte, error) {
	var content []byte
	var curBlock Block
	curBlockUUID := fileptr.FirstBlock
	for curBlockUUID != uuid.Nil {
		// Unmarshal current block
		marshaledBlock, ok := userlib.DatastoreGet(curBlockUUID)
		if !ok || marshaledBlock == nil {
			return nil, fmt.Errorf("block not found")
		}
		err := json.Unmarshal(marshaledBlock, &curBlock)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("no block found")
		}

		// Check integrity of block
		hash, err := curBlock.ComputeIntegrity(macKey)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(hash, curBlock.Integrity) {
			return nil, fmt.Errorf("mismatching mac")
		}

		// Decrypt content and append to current content
		decContent := userlib.SymDec(symKey, curBlock.Content)
		content = append(content, decContent...)

		// Move to next block
		curBlockUUID = curBlock.NextBlock
	}
	//userlib.DebugMsg("Content is: <%v>", content)
	return content, nil
}

func (file *File) UpdateKeys(user *User, symKey []byte, macKey []byte, signatureSK userlib.DSSignKey) error {
	for i := 0; i < len(file.AuthorizedAccess); i++ {
		entry := file.AuthorizedAccess[i]
		if entry.Username != "" {
			creds, err := RetrieveCredEntry(entry.Username)
			if err != nil {
				return err
			}
			if creds == nil {
				return fmt.Errorf("idk why there's no user")
			}

			// Validate entry
			signerCreds, err := RetrieveCredEntry(entry.SignedBy)
			if err != nil {
				return err
			}
			if signerCreds == nil {
				return fmt.Errorf("there was no user with username %v", entry.SignedBy)
			}
			signature := entry.Signature
			err = CheckSignature(signature, signerCreds.SignaturePK, &entry)
			if err != nil {
				return err
			}

			// Reassign key
			userFileSharePK, err := KeystoreGetHelper(creds.FileSharePK)
			if err != nil {
				return err
			}

			encSymKey, err := userlib.PKEEnc(*userFileSharePK, symKey)
			if err != nil {
				return err
			}
			encMacKey, err := userlib.PKEEnc(*userFileSharePK, macKey)
			if err != nil {
				return err
			}
			file.AuthorizedAccess[i].DecryptionKey = encSymKey
			file.AuthorizedAccess[i].MacKey = encMacKey
			file.AuthorizedAccess[i].SignedBy = user.Username
			err = file.AuthorizedAccess[i].Sign(signatureSK)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (fileptr *File) FindAuthorizedUser(username string) (*SharedFileAccess, int, error) {
	for i := 0; i < len(fileptr.AuthorizedAccess); i++ {
		entry := fileptr.AuthorizedAccess[i]
		//userlib.DebugMsg("Found entry %v", entry.Username)
		if entry.Username == username {
			creds, err := RetrieveCredEntry(username)
			if err != nil {
				return nil, -1, err
			}
			if creds == nil {
				return nil, -1, fmt.Errorf("%v is on Authorized Users, but no Credentials found", username)
			}

			// Validate entry
			validSigner := false
			for j := 0; j < len(fileptr.AuthorizedAccess); j++ {
				if fileptr.AuthorizedAccess[j].Username == entry.SignedBy {
					validSigner = true
				}
			}
			if !validSigner {
				return nil, -1, fmt.Errorf("signer %v is not an authorized user", entry.SignedBy)
			}
			signerCreds, err := RetrieveCredEntry(entry.SignedBy)
			if err != nil {
				return nil, -1, err
			}
			if signerCreds == nil {
				return nil, -1, fmt.Errorf("there was no user with username %v", entry.SignedBy)
			}
			signature := entry.Signature
			//userlib.DebugMsg("(FindAuthorizedUser) Checking signature on credentials -->")
			//userlib.DebugMsg("Val: %v...%v", signerCreds.Signature[:4], signerCreds.Signature[252:])
			err = CheckSignature(signature, signerCreds.SignaturePK, &entry)
			if err != nil {
				return nil, -1, err
			}
			return &entry, i, nil
		}
	}
	return nil, -1, nil
}

func (file *File) NamesToRevoke(username string) ([]string, error) {
	var toRemove []string
	cur, index, err := file.FindAuthorizedUser(username)
	if err != nil {
		return nil, err
	}
	if cur == nil || index == -1 {
		// may not have accepted yet
		return nil, nil
	}
	toRemove = append(toRemove, username)
	//userlib.DebugMsg("Children of %v: %v", username, cur.Children)
	for i := 0; i < len(cur.Children); i++ {
		recurse, err := file.NamesToRevoke(cur.Children[i])
		if err != nil {
			return nil, err
		}
		toRemove = append(toRemove, recurse...)
	}

	var emptyVal SharedFileAccess
	file.AuthorizedAccess[index] = emptyVal
	return toRemove, nil
}
