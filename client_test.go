package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	"encoding/hex"
	_ "encoding/hex"
	"encoding/json"
	_ "errors"
	_ "strconv"
	"strings"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

var allFalse = [...]bool{false, false, false, false, false, false, false, false}

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

// For basic deleting/modifying values
func ValidActions() (*client.User, *client.User, *client.User, uuid.UUID) {
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"

	alice, err := client.InitUser("alice", defaultPassword)
	Expect(err).To(BeNil())
	bob, err := client.InitUser("bob", defaultPassword)
	Expect(err).To(BeNil())
	charles, err := client.InitUser("charles", defaultPassword)
	Expect(err).To(BeNil())

	err = bob.StoreFile(bobFile, []byte(contentOne))
	Expect(err).To(BeNil())
	err = alice.StoreFile(aliceFile, []byte(contentOne))
	Expect(err).To(BeNil())
	err = alice.StoreFile(bobFile, []byte(contentOne))
	Expect(err).To(BeNil())
	err = alice.StoreFile(charlesFile, []byte(contentOne))
	Expect(err).To(BeNil())

	// Bob accepts valid --> Bob can't receive a revoke
	inviteOne, err := alice.CreateInvitation(aliceFile, "bob")
	Expect(err).To(BeNil())

	err = bob.AcceptInvitation("alice", inviteOne, aliceFile)
	Expect(err).To(BeNil())

	// Charles accepts valid --> Bob can't send revoke
	inviteTwo, err := bob.CreateInvitation(bobFile, "charles")
	Expect(err).To(BeNil())

	err = charles.AcceptInvitation("bob", inviteTwo, charlesFile)
	Expect(err).To(BeNil())

	// Alice sends valid --> Bob can't accept invite
	inviteThree, err := alice.CreateInvitation(charlesFile, "bob")
	Expect(err).To(BeNil())

	return alice, bob, charles, inviteThree
}

// After things have been tampered with or deleted
func InvalidActions(alice *client.User, bob *client.User, charles *client.User, inviteThree uuid.UUID, args [8]bool) {
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"

	validGetUser := args[0]
	validStore := args[1]
	validAppend := args[2]
	validLoad := args[3]
	validAcceptInvite := args[4]
	validSendInvite := args[5]
	validSendRevoke := args[6]
	validReceiveRevoke := args[7]

	//If "valid_<action>" is true, it should not error. Else it should

	//userlib.DebugMsg("GetUser without credentials")
	bobLaptop, err := client.GetUser("bob", defaultPassword)
	if validGetUser {
		Expect(err).To(BeNil())
		Expect(bobLaptop).NotTo(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
		Expect(bobLaptop).To(BeNil())
	}

	//userlib.DebugMsg("StoreFile without credentials")
	err = bob.StoreFile(bobFile, []byte(contentTwo))
	if validStore {
		Expect(err).To(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
	}

	content, err := bob.LoadFile(bobFile)
	if validLoad {
		Expect(err).To(BeNil())
		if validStore {
			Expect(content).To(Equal(contentTwo))
		} else {
			Expect(content).To(Equal(contentOne))
		}

	} else {
		Expect(err).NotTo(BeNil())
		Expect(content).To(BeNil())
	}

	//userlib.DebugMsg("Append no creds")
	err = bob.AppendToFile(bobFile, []byte(contentThree))
	if validAppend {
		Expect(err).To(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
	}

	//userlib.DebugMsg("Accept no creds")
	err = bob.AcceptInvitation("alice", inviteThree, charlesFile)
	if validAcceptInvite {
		Expect(err).To(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
	}

	//userlib.DebugMsg("Inviter no creds")
	badInvite, err := bob.CreateInvitation(bobFile, "alice")
	if validSendInvite {
		Expect(err).To(BeNil())
		Expect(badInvite).NotTo(Equal(uuid.Nil))
	} else {
		Expect(err).NotTo(BeNil())
		Expect(badInvite).To(Equal(uuid.Nil))
	}

	//userlib.DebugMsg("Invitee has no creds")
	inviteTwo, err := alice.CreateInvitation(bobFile, "bob")
	if validAcceptInvite {
		Expect(err).To(BeNil())
		Expect(inviteTwo).NotTo(Equal(uuid.Nil))
	} else {
		Expect(err).NotTo(BeNil())
		Expect(inviteTwo).To(Equal(uuid.Nil))
	}

	//userlib.DebugMsg("Revoke no creds")
	err = alice.RevokeAccess(aliceFile, "bob")
	if validReceiveRevoke {
		Expect(err).To(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
	}

	//userlib.DebugMsg("Can't send a revoke")
	err = bob.RevokeAccess(bobFile, "charles")
	if validSendRevoke {
		Expect(err).To(BeNil())
	} else {
		Expect(err).NotTo(BeNil())
	}
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Datastore Adversary Tests", func() {
		// Note to self: Credentials, User, FileDesc, File, Block, Invitation
		Specify("Deleting credentials struct", func() {
			userlib.DebugMsg("Deleting credentials")
			// Valid operations
			alice, bob, charles, inviteThree := ValidActions()

			// Get the datastore key for bob's credentials
			datastoreKey := "Credentials/bob"
			hash := userlib.Hash([]byte(datastoreKey))
			generatedUUID, err := uuid.FromBytes(hash[:16])
			Expect(err).To(BeNil())

			// Delete bob's credentials
			userlib.DatastoreDelete(generatedUUID)

			// Invalid operations
			InvalidActions(alice, bob, charles, inviteThree, allFalse)
		})

		Specify("Modifying Credentials struct to change a password", func() {
			userlib.DebugMsg("Modifying credentials")
			// Valid operations
			alice, bob, charles, inviteThree := ValidActions()

			// Get the datastore key for bob's credentials
			datastoreKey := "Credentials/bob"
			hash := userlib.Hash([]byte(datastoreKey))
			generatedUUID, err := uuid.FromBytes(hash[:16])
			Expect(err).To(BeNil())

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

			// Unmarshal bob's credentials
			var newCreds Credentials
			marshaledOld, ok := userlib.DatastoreGet(generatedUUID)
			Expect(ok).To(BeTrue())
			json.Unmarshal(marshaledOld, newCreds)

			// Change bob's password to something we want
			newPassword := "hackerWord"
			newPbk := userlib.Argon2Key([]byte(newPassword), newCreds.PasswordSalt, 16)
			newPasswordHash := userlib.Hash(newPbk)

			newCreds.Password = newPasswordHash

			// Store in datastore
			marshaledNew, err := json.Marshal(newCreds)
			Expect(err).To(BeNil())
			userlib.DatastoreSet(generatedUUID, marshaledNew)

			// Attempt to login as bob
			hacker, err := client.GetUser("bob", newPassword)
			Expect(err).ToNot(BeNil())
			Expect(hacker).To(BeNil())

			// Invalid operations
			InvalidActions(alice, bob, charles, inviteThree, allFalse)
		})
	})

	Describe("Revoked User adversary", func() {
		Specify("Alice shares with Bob who shares with charles. Alice revokes bob before charles accepts", func() {
			userlib.DebugMsg("Revoking before accepting")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			inviteOne, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inviteOne, bobFile)
			Expect(err).To(BeNil())

			inviteTwo, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", inviteTwo, charlesFile)
			Expect(err).NotTo(BeNil())
		})

		Specify("Revoking from one user leaves other users unaffected", func() {
			//						alice
			//				bob				 charles
			//			doris           frank        grace
			//		eve                            ira     horace
			//
			userlib.DebugMsg("Complicated Tree test")
			// Init users
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			// Store file at Depth 0
			err = alice.StoreFile(aliceFile, []byte("alice"))
			Expect(err).To(BeNil())

			// Depth 1
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			// Bob adds
			err = bob.AppendToFile(bobFile, []byte("bob"))
			Expect(err).To(BeNil())

			// Left tree
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())
			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			// Eve adds
			err = eve.AppendToFile(eveFile, []byte("eve"))

			// Right tree Depths 1 and 2
			invite, err = charles.CreateInvitation(charlesFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("charles", invite, frankFile)
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("charles", invite, graceFile)
			Expect(err).To(BeNil())

			// Frank loads
			content, err := frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("alicebobeve")))

			// Grace invites ira
			invite, err = grace.CreateInvitation(graceFile, "ira")
			Expect(err).To(BeNil())
			err = ira.AcceptInvitation("grace", invite, iraFile)
			Expect(err).To(BeNil())

			// Charles revokes grace
			err = charles.RevokeAccess(charlesFile, "grace")
			Expect(err).To(BeNil())

			// Grace tries to invite horace (who tries to accept) and ira tries to append *FAIL*
			invite, err = grace.CreateInvitation(graceFile, "horace")
			Expect(err).NotTo(BeNil())
			Expect(invite).To(Equal(uuid.Nil))
			err = horace.AcceptInvitation("grace", invite, horaceFile)
			Expect(err).NotTo(BeNil())
			err = ira.AppendToFile(iraFile, []byte("ira"))
			Expect(err).NotTo(BeNil())

			// Doris loads
			content, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("alicebobeve")))

			// Frank overwrites
			err = frank.StoreFile(frankFile, []byte("frank rulez"))
			Expect(err).To(BeNil())

			// Charles gets angry and revokes frank
			err = charles.RevokeAccess(charlesFile, "frank")
			Expect(err).To(BeNil())

			// Bob overwrites
			err = bob.StoreFile(bobFile, []byte("frank suckz"))
			Expect(err).To(BeNil())

			// Alice loads
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("frank suckz")))

			// Doris invites ira
			invite, err = doris.CreateInvitation(dorisFile, "ira")
			Expect(err).To(BeNil())

			// Ira accepts
			err = ira.AcceptInvitation("doris", invite, "iraV2")
			Expect(err).To(BeNil())

			// Ira Loads
			content, err = ira.LoadFile("iraV2")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("frank suckz")))

			// Ira overwrites
			err = ira.StoreFile("iraV2", []byte("welcome to whoville"))
			Expect(err).To(BeNil())

			// Charles loads
			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("welcome to whoville")))

		})
	})

	Describe("Load testing", func() {
		//return
		Specify("Storing and appending multiple blocks", func() {
			userlib.DebugMsg("Load test 1")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			longFileContent := strings.Repeat("banana", 100)
			err = alice.StoreFile("fruit.txt", []byte(longFileContent))
			Expect(err).To(BeNil())

			content, err := alice.LoadFile("fruit.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(longFileContent)))

			fruit2 := strings.Repeat("apple", 40)
			err = alice.AppendToFile("fruit.txt", []byte(fruit2))
			Expect(err).To(BeNil())
			content, err = alice.LoadFile("fruit.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(longFileContent + fruit2)))
		})

		Specify("Long username or password", func() {
			//return
			userlib.DebugMsg("Load Test 2")
			securePassword := hex.EncodeToString(userlib.RandomBytes(10000000))
			alice, err = client.InitUser(securePassword, securePassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser(securePassword, securePassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("longfile.txt", []byte(securePassword))
			Expect(err).To(BeNil())
			err = alice.AppendToFile("longfile.txt", []byte("hi"))
			Expect(err).To(BeNil())
			content, err := alice.LoadFile("longfile.txt")
			Expect(err).To(BeNil())
			Expect(len(content)).To(Equal(len(securePassword) + 2))
			expectedContent := securePassword + "hi"
			Expect(content[len(content)-10]).To(Equal(expectedContent[len(expectedContent)-10]))
		})
	})

	Describe("Basic Tests", func() {
		//return
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Basic Test 1")
			//userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Basic Test 2")
			//userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Basic Test 3")
			//userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			//userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			//userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			//userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Basic Test 4")
			//userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			//userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			//userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			//userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			//userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			//userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			//userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Error coverage on Client API without a third party", func() {
		//return
		Specify("InitUser.", func() {
			userlib.DebugMsg("Basic Error Test 1")
			//userlib.DebugMsg("Initializing a user with no name.")
			nobody, err := client.InitUser("", defaultPassword)
			Expect(err.Error()).To(Equal("username cannot be empty"))
			Expect(nobody).To(BeNil())

			//userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Initializing user Alice again.")
			aliceTwo, err := client.InitUser("alice", "overwrite password")
			Expect(err.Error()).To(Equal("user with name alice already exists"))
			Expect(aliceTwo).To(BeNil())
		})

		Specify("GetUser.", func() {
			userlib.DebugMsg("Basic Error Test 2")
			//userlib.DebugMsg("Retrieving a user that does not exist.")
			nobody, err := client.GetUser("john", "doe")
			Expect(err.Error()).To(Equal("there was no user with username john"))
			Expect(nobody).To(BeNil())

			//userlib.DebugMsg("Initializing user Alice with no password.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Log in as Alice with an incorrect password.")
			aliceImposter, err := client.GetUser("alice", defaultPassword)
			Expect(err.Error()).To(Equal("incorrect password"))
			Expect(aliceImposter).To(BeNil())

			//userlib.DebugMsg("Log in as Alice with no password.")
			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).To(BeNil())
		})

		Specify("StoreFile, Loadfile and AppendFile", func() {
			userlib.DebugMsg("Basic Error Test 3")
			//userlib.DebugMsg("Initializing user (case sensitive) alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Initializing user (case sensitive) Alice.")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing a file for alice.")
			err = alice.StoreFile("burger.txt", []byte("hamburg"))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing a file for Alice.")
			err = bob.StoreFile("burger2.txt", []byte("cheeseburg"))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Loading a file that doesn't exist in Alice's space")
			content, err := bob.LoadFile("burger.txt")
			Expect(err.Error()).To(Equal("File does not exist in the space of Alice"))
			Expect(content).To(BeNil())

			//userlib.DebugMsg("Appending to a file that doesn't exist in Alice's space")
			err = bob.AppendToFile("burger.txt", []byte("lettuceburg"))
			Expect(err.Error()).To(Equal("not authorized to append to this file"))
		})

		Specify("CreateInvitation and AcceptInvitation", func() {
			userlib.DebugMsg("Basic Error Test 4")

			//userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Initializing another session for alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Send invite to a user who doesn't exist.")
			invite, err := alice.CreateInvitation(aliceFile, "ghost")
			Expect(err.Error()).To(Equal("this user does not exist"))
			Expect(invite).To(Equal(uuid.Nil))

			//userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Sharing invalid file to bob.")
			invite, err = alice.CreateInvitation("notreal.txt", "bob")
			Expect(err.Error()).To(Equal("file not existing"))
			Expect(invite).To(Equal(uuid.Nil))

			//userlib.DebugMsg("Storing file")
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Send invite to a file bob already has.")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Accept invite for a file bob already has.")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err.Error()).To(Equal("file already exists for user bob"))

			//userlib.DebugMsg("Expect bob's file to be unchanged")
			content, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))
		})

		Specify("AcceptInvitation, Part 2", func() {
			userlib.DebugMsg("Basic Error Test 5")
			//userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Sharing file to bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Bob accepts the invite from the wrong person")
			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).NotTo(BeNil())

			//userlib.DebugMsg("Alice can still load the file")
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))
		})

		Specify("RevokeAccess", func() {
			userlib.DebugMsg("Basic Error Test 6")
			//userlib.DebugMsg("Initializing users alice, bob, and charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Sharing file to bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Bob accepts the invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("alice revokes file with bad input")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err.Error()).To(Equal("file not shared with this user"))

			err = alice.RevokeAccess(aliceFile, "helloworld")
			Expect(err.Error()).ToNot(BeNil())

			err = charles.RevokeAccess(aliceFile, "alice")
			Expect(err.Error()).To(Equal("file nonexistent here"))
		})
	})

	Describe("More specific bug-inducing tests", func() {
		//return
		Specify("Storing and appending to a file with empty contents.", func() {
			userlib.DebugMsg("Testing empty contents")
			//userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Storing a file with empty contents.")
			err = alice.StoreFile("empty.txt", nil)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Appending nothing to an empty file.")
			err = alice.AppendToFile("empty.txt", []byte{})
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Loading a file with empty contents.")
			content, err := alice.LoadFile("empty.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte{}))

			//userlib.DebugMsg("Append something to an empty file.")
			err = alice.AppendToFile("empty.txt", []byte("no longer empty"))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Loading a file.")
			content, err = alice.LoadFile("empty.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("no longer empty")))

			//userlib.DebugMsg("Append nothing to a file with some contents.")
			err = alice.AppendToFile("empty.txt", []byte{})
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Loading a file.")
			content, err = alice.LoadFile("empty.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("no longer empty")))
		})

		Specify("Storing a file that already exists.", func() {
			userlib.DebugMsg("Testing overwrites")
			//userlib.DebugMsg("Initializing users and storing file.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte("individual"))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(" self"))
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Share file with bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			//userlib.DebugMsg("Overwrite file")
			err = bob.StoreFile(bobFile, []byte("comrade"))
			Expect(err).To(BeNil())

			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("comrade")))

			err = alice.AppendToFile(aliceFile, []byte(" group"))
			Expect(err).To(BeNil())

			content, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("comrade group")))
		})
	})
})
