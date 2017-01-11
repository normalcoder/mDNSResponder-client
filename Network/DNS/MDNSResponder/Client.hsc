{-# LANGUAGE GADTs, GeneralizedNewtypeDeriving, RecordWildCards #-}
{-# LANGUAGE ExistentialQuantification, Rank2Types #-}
{-|
Module : Network.DNS.MDNSResponder.Client
Description : Library for talking to the mDNSResponder daemon.
Copyright : (c) 2016, Obsidian Systems LLC
License: BSD3
Maintainer : shea@shealevy.com
Stability : experimental
-}
module Network.DNS.MDNSResponder.Client
  ( -- * Managing connections
    Connection
  , connect
  , disconnect
  , defaultAddr
  , AsyncConnectionError (..)
  , AsyncConnectionErrorHandler
    -- * Data types
  , NullFreeByteString
    -- ** Flags
  , DNSServiceFlags
    -- ** Error codes
  , DNSServiceErrorType
  , kDNSServiceErr_NoError
  , kDNSServiceErr_ServiceNotRunning
  , kDNSServiceErr_ShortResponse
    -- ** Interface indices
  , InterfaceIndex
  , kDNSServiceInterfaceIndexAny
  , kDNSServiceInterfaceIndexLocalOnly
    -- * Requests
  , Request (..)
  , request
    -- * Responses
  , AsyncResponseHandler
  , ResponseHeader (..)
  , Response (..)
  , NTDResponse (..)
  , ResolveResponse (..)
  ) where

#include "dnssd_ipc.h"
#include <sys/socket.h>

import Data.Word
import Data.Int
import Data.Bits
import Data.IORef
import Data.Typeable
import System.Environment
import Control.Exception
import Control.Concurrent
import Control.Monad
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Storable
import Foreign.C.Types
import Foreign.C.String

import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class

import Data.ByteString as BS
import Data.ByteString.Unsafe

import Data.Endian

import qualified Control.Concurrent.Map as CM

import qualified Network.Socket as S

import Network.Socket.Msg

-- | Flag type for API calls. 
newtype DNSServiceFlags =
  DNSServiceFlags #{type DNSServiceFlags} deriving (Eq, Bits)

instance Monoid DNSServiceFlags where
  mempty = DNSServiceFlags 0
  mappend = (.|.)

-- | An index to specify on which interface a service exists.
newtype InterfaceIndex = InterfaceIndex Word32

-- | The service is served on any interface.
kDNSServiceInterfaceIndexAny :: InterfaceIndex
kDNSServiceInterfaceIndexAny =
  InterfaceIndex #{const kDNSServiceInterfaceIndexAny}

-- | The service is only served to the local host.
kDNSServiceInterfaceIndexLocalOnly :: InterfaceIndex
kDNSServiceInterfaceIndexLocalOnly =
  InterfaceIndex #{const kDNSServiceInterfaceIndexLocalOnly}

-- | Error codes returned by the daemon.
newtype DNSServiceErrorType =
  DNSServiceErrorType #{type DNSServiceErrorType}
    deriving (Eq, Show)

-- | There was no error.
kDNSServiceErr_NoError :: DNSServiceErrorType
kDNSServiceErr_NoError =
  DNSServiceErrorType #{const kDNSServiceErr_NoError}

-- | The daemon is not running/closed the connection.
--
-- You should still call 'disconnect' to clean up resources!
kDNSServiceErr_ServiceNotRunning :: DNSServiceErrorType
kDNSServiceErr_ServiceNotRunning =
  DNSServiceErrorType (#{const kDNSServiceErr_ServiceNotRunning})

-- | The response sent by the daemon was too short.
--
-- This is not an upstream error code, the official Apple client just
-- declines to call the callback in this case. It is outside of the
-- documented range for mDNS error codes.
kDNSServiceErr_ShortResponse :: DNSServiceErrorType
kDNSServiceErr_ShortResponse = DNSServiceErrorType 1

-- | A 'ByteString' with no null characters.
--
-- This invariant must be maintained by the caller.
type NullFreeByteString = ByteString

-- | The shared header for daemon responses.
--
-- The header also contains an error code on the wire, but it's always
-- 'kDNSServiceErr_NoError' on code paths that get passed a header.
data ResponseHeader = ResponseHeader
  { reshdr_flags :: !DNSServiceFlags -- ^ Flags applicable to the
                                     -- response.
  , reshdr_ifi :: !InterfaceIndex -- ^ The interface in question.
  }

-- | A response with its header.
data Response a = Response !ResponseHeader !a

-- | A response containing a name, registration type, and domain.
data NTDResponse = NTDResponse
  { ntd_name :: !NullFreeByteString -- ^ The service name.
  , ntd_regtype :: !NullFreeByteString -- ^ The service registration
                                       -- type.
  , ntd_domain :: !NullFreeByteString -- ^ The domain on which the
                                      -- service is registered.
  }

-- | A response to a 'ServiceResolve' request.
data ResolveResponse = ResolveResponse
  { resolve_fullname :: !NullFreeByteString -- ^ The full service
                                            -- domain name.
  , resolve_hosttarget :: !NullFreeByteString -- ^ The hostname of the
                                              -- machine providing
                                              -- the service.
  , resolve_port :: !S.PortNumber -- ^ The port number the service is
                                  -- served on.
  , resolve_txt :: !ByteString -- ^ The primary TXT record for the
                               -- service.
  }

-- | A request to the mDNSResponder daemon.
--
-- Parameterized by the type of the response.
--
-- Constructor fields documented with the constructor due to
-- https://ghc.haskell.org/trac/ghc/ticket/12050
--
-- See also the documentation for these requests in dns_sd.h
data Request a where
  -- | Register a service.
  --
  -- Fields:
  --
  -- 1. flags: Indicate behavior on name conflict.
  -- 2. index: The interface(s) on which to register the service.
  -- 3. name: The service name to be registered, or 'empty' for the
  --    default.
  -- 4. type: The service type followed by the protocol, separated by
  --    a dot.
  -- 5. domain: The domain on which to advertise, or 'empty' for the
  --    default domains.
  -- 6. host: The SRV target host name, or 'empty' for the default
  --    host name(s).
  -- 7. port: The port the service listens on.
  -- 8. txt: The text record data, or 'empty' for none.
  ServiceRegister :: !DNSServiceFlags
                  -> !InterfaceIndex
                  -> !NullFreeByteString
                  -> !NullFreeByteString
                  -> !NullFreeByteString
                  -> !NullFreeByteString
                  -> !S.PortNumber
                  -> !ByteString
                  -> Request NTDResponse
  -- | Browse for a service.
  --
  -- Fields:
  --
  -- 1. index: The interface(s) on which to browse.
  -- 2. regtype: The service type being browsed for followed by the
  --    protocol, with optional subtypes or group IDs.
  -- 3. domain: The domain on which to browse, or 'empty' for the
  --    default.
  ServiceBrowse :: !InterfaceIndex
                -> !NullFreeByteString
                -> !NullFreeByteString
                -> Request NTDResponse
  -- | Resolve a service.
  --
  -- You probably want to populate the name, regtype, and domain from
  -- the results of a 'ServiceBrowse' request.
  --
  -- Fields:
  --
  -- 1. flags: Specify multicast behavior.
  -- 2. index: The interface(s) on which to resolve.
  -- 3. name: The name of the service to be resolved.
  -- 4. regtype: The type of the service to be resolved.
  -- 5. domain: The domain of the service to be resolved.
  ServiceResolve :: !DNSServiceFlags
                 -> !InterfaceIndex
                 -> !NullFreeByteString
                 -> !NullFreeByteString
                 -> !NullFreeByteString
                 -> Request ResolveResponse

-- | A connection to the daemon.
data Connection = Connection
  { sock :: !S.Socket
  , counter :: !(IORef Word64)
  , requestQueue :: !(Chan AnyRequestRegistration)
  , responseMap :: !(CM.Map Word64 AnyAsyncResponseHandler)
  , recvThreadId :: !ThreadId
  , sendThreadId :: !ThreadId
  }

-- | An error communicating with the daemon.
data AsyncConnectionError
  = AsyncConnectionIOError !IOError -- ^ An 'IOError' occured while
                                    -- using the socket.
  | AsyncConnectionClosedError -- ^ The daemon closed the socket
                               -- unexpectedly.
  | AsyncConnectionBadDaemonVersionError !Word32 -- ^ The daemon
                                                 -- reported a version
                                                 -- we can't handle.
    deriving (Show, Typeable)

instance Exception AsyncConnectionError

-- | Handle a generic error communicating with the daemon.
--
-- These errors may occur at any time, are not associated with any
-- particular request, and are not generally recoverable. You should
-- still call 'disconnect' to clean up resources after recieving an
-- error.
--
-- The handler is called in its own thread.
type AsyncConnectionErrorHandler = AsyncConnectionError -> IO ()

-- | Connect to the daemon.
connect :: S.SockAddr -- ^ The address of the daemon.
                      --
                      -- You probably want 'defaultAddr'. In any case,
                      -- the implementation currently only works for
                      -- AF_UNIX-based daemons, even though there are
                      -- AF_INET-based daemons in existence.
        -> AsyncConnectionErrorHandler
        -> IO (Either DNSServiceErrorType Connection)
connect addr e_handler = bracketOnError makeSocket S.close $ \s -> do
    S.connect s addr
    allocaBytes ipcMsgHdrSz $ \hdr -> do
      pokeHdr (IpcMsgHdr 0 #{const connection_request} 0) hdr
      sendAll s (castPtr hdr) ipcMsgHdrSz
    err <- recvError s
    case err of
      DNSServiceErrorType #{const kDNSServiceErr_NoError} -> do
        chan <- newChan
        handlers <- CM.empty
        sTidVar <- newEmptyMVar
        rTidVar <- newEmptyMVar
        counter' <- newIORef 0
        bracketOnError
          (createSendThread s chan sTidVar rTidVar)
          killThread $ \sTid -> do
          bracketOnError
            (createRecvThread s handlers sTidVar rTidVar)
            killThread $ \rTid -> do
            return . Right $
              Connection s counter' chan handlers rTid sTid
      _ -> return $ Left err
  where
    makeSocket = S.socket S.AF_UNIX S.Stream S.defaultProtocol

    createSendThread s chan sTidVar rTidVar =
      mask_ $ forkIOWithUnmask $
        sendThread s chan e_handler sTidVar rTidVar

    createRecvThread s handlers sTidVar rTidVar =
      mask_ $ forkIOWithUnmask $
        recvThread s handlers e_handler sTidVar rTidVar

-- | The default address for the daemon.
defaultAddr :: IO S.SockAddr
defaultAddr = do
  m_def <- lookupEnv "DNSSD_UDS_PATH" -- Not cross-compilation safe: #{const_str MDNS_UDS_SERVERPATH_ENVVAR}
  let p = case m_def of
            Just p' -> p'
            Nothing -> "/var/run/mDNSResponder" -- Not cross-compilation safe: #{const_str MDNS_UDS_SERVERPATH}
  return $ S.SockAddrUnix p

-- | Disconnect from the daemon.
--
-- It is an error to use the passed in 'Connection' during or after
-- this call, though it is safe to call this again if it fails due
-- to an asynchronous exception.
disconnect :: Connection
           -> IO ()
disconnect (Connection {..}) = do
  killThread recvThreadId
  killThread sendThreadId
  S.close sock

-- | Handle asynchronous responses to a request.
--
-- Some requests result in multiple responses.
--
-- The handler is called on its own thread.
type AsyncResponseHandler a = Either DNSServiceErrorType (Response a)
                            -> IO ()

recvError :: S.Socket -> IO DNSServiceErrorType
recvError s = alloca $ \buf -> do
  res <- recvAll s (castPtr buf) #{size DNSServiceErrorType}
  case res of
    RecvAllOK -> DNSServiceErrorType . fromBigEndian <$> peek buf
    RecvAllClosed -> return kDNSServiceErr_ServiceNotRunning

-- | Send a request to the daemon.
--
-- The 'PeekableResponse' constraint is an implementation detail, all
-- 'Request's have a type appropriate for 'request'. Unfortunately,
-- it doesn't seem possible to hide this constraint from the haddock
-- docs.
request :: PeekableResponse a
        => Connection
        -> Request a
        -> AsyncResponseHandler a
        -> IO DNSServiceErrorType -- ^ The immediate error from the
                                  -- daemon, if any. Even if
                                  -- 'kDNSServiceErr_NoError' is
                                  -- returned here, there still may be
                                  -- asynchronous errors for this
                                  -- request.
request (Connection {..}) req handler =
    bracket makeSocks closeSocks $ \(us, them) -> do
      ctx <- atomicModifyIORef' counter (\x -> (x + 1, x + 1))
      CM.insert ctx (AnyAsyncResponseHandler handler) responseMap
      writeChan requestQueue (AnyRequestRegistration ctx req them)
      recvError us
  where
    makeSocks = S.socketPair S.AF_UNIX S.Stream S.defaultProtocol
    closeSocks (us, them) = S.close us >> S.close them

data AnyAsyncResponseHandler = forall a . PeekableResponse a =>
  AnyAsyncResponseHandler !(AsyncResponseHandler a)

data AnyRequestRegistration =
  forall a . AnyRequestRegistration !Word64 !(Request a) !S.Socket

data IpcMsgHdr = IpcMsgHdr
  { datalen :: !Word32
  , op :: !Word32
  , context :: !Word64
  }

ipcMsgHdrSz :: Int
ipcMsgHdrSz = #{size ipc_msg_hdr}

pokeHdr :: IpcMsgHdr
        -> (Ptr IpcMsgHdr)
        -> IO ()
pokeHdr (IpcMsgHdr {..})  hdr = do
  #{poke ipc_msg_hdr, version} hdr $
    toBigEndian (#{const VERSION} :: Word32)
  #{poke ipc_msg_hdr, datalen} hdr $ toBigEndian datalen
  #{poke ipc_msg_hdr, ipc_flags} hdr (0 :: Word32)
  #{poke ipc_msg_hdr, op} hdr $ toBigEndian op
  #{poke ipc_msg_hdr, client_context} hdr context
  #{poke ipc_msg_hdr, reg_index} hdr (0 :: Word32)

peekHdr :: Ptr IpcMsgHdr -> IO IpcMsgHdr
peekHdr hdr = do
  ver <-
    (fromBigEndian <$> #{peek ipc_msg_hdr, version} hdr) :: IO Word32
  case ver of
    #{const VERSION} -> do
      datalen <- fromBigEndian <$> #{peek ipc_msg_hdr, datalen} hdr
      op <- fromBigEndian <$> #{peek ipc_msg_hdr, op} hdr
      context <- #{peek ipc_msg_hdr, client_context} hdr
      return $ IpcMsgHdr datalen op context
    _ -> throwIO $ AsyncConnectionBadDaemonVersionError ver

size :: Request a -> Int
size (ServiceRegister _ _ name ty domain host _ txt) =
  #{size DNSServiceFlags} +
  4 + -- InterfaceIndex, Word32
  (BS.length name) + 1 +
  (BS.length ty) + 1 +
  (BS.length domain) + 1 +
  (BS.length host) + 1 +
  2 + -- Port
  2 + -- txtLen
  (BS.length txt)
size (ServiceBrowse _ ty domain) =
  #{size DNSServiceFlags} +
  4 + -- InterfaceIndex, Word32
  (BS.length ty) + 1 +
  (BS.length domain) + 1
size (ServiceResolve _ _ name regtype domain) =
  #{size DNSServiceFlags} +
  4 + -- InterfaceIndex, Word32
  (BS.length name) + 1 +
  (BS.length regtype) + 1 +
  (BS.length domain) + 1

operation :: Request a -> Word32
operation (ServiceRegister _ _ _ _ _ _ _ _) =
  #{const reg_service_request}
operation (ServiceBrowse _ _ _) = #{const browse_request}
operation (ServiceResolve _ _ _ _ _) = #{const resolve_request}

type Poke =
  (Ptr Word8 -> IO (), Int)

runPokes :: Ptr Word8 -> [ Poke ] -> IO ()
runPokes _ [] = return ()
runPokes p ((io, sz) : pokes) = do
  io p
  runPokes (plusPtr p sz) pokes

pokeBSNull :: Int -> ByteString -> Ptr Word8 -> IO ()
pokeBSNull sz bs ptr = do
  pokeBS sz bs ptr
  poke (plusPtr ptr sz) (0 :: Word8)

pokeBS :: Int -> ByteString -> Ptr Word8 -> IO ()
pokeBS sz bs ptr = unsafeUseAsCString bs $ \buf -> do
  copyBytes ptr (castPtr buf) sz

pokeBody :: Request a -> Ptr (Request a) -> IO ()
pokeBody (ServiceRegister
          (DNSServiceFlags flags)
          (InterfaceIndex ifi)
          name
          ty
          domain
          host
          port
          txt
         ) ptr = runPokes (castPtr ptr)
    [ (flip poke (toBigEndian flags) . castPtr, 4)
    , (flip poke (toBigEndian ifi) . castPtr, 4)
    , (pokeBSNull name_sz name, name_sz + 1)
    , (pokeBSNull ty_sz ty, ty_sz + 1)
    , (pokeBSNull domain_sz domain, domain_sz + 1)
    , (pokeBSNull host_sz host, host_sz + 1)
    , (flip poke port . castPtr, 2)
    , (flip poke (toBigEndian txtln) . castPtr, 2)
    , (pokeBS txt_sz txt, txt_sz)
    ]
  where
    name_sz = BS.length name
    ty_sz = BS.length ty
    domain_sz = BS.length domain
    host_sz = BS.length host
    txtln :: Word16
    txtln = fromIntegral txt_sz
    txt_sz = BS.length txt
pokeBody (ServiceBrowse (InterfaceIndex ifi) ty domain) ptr =
    runPokes (castPtr ptr)
    [ (flip poke (0 :: Word32) . castPtr, 4)
    , (flip poke (toBigEndian ifi) . castPtr, 4)
    , (pokeBSNull ty_sz ty, ty_sz + 1)
    , (pokeBSNull domain_sz domain, domain_sz + 1)
    ]
  where
    ty_sz = BS.length ty
    domain_sz = BS.length domain
pokeBody (ServiceResolve
          (DNSServiceFlags flags)
          (InterfaceIndex ifi)
          name
          ty
          domain
         ) ptr = runPokes (castPtr ptr)
    [ (flip poke (toBigEndian flags) . castPtr, 4)
    , (flip poke (toBigEndian ifi) . castPtr, 4)
    , (pokeBSNull name_sz name, name_sz + 1)
    , (pokeBSNull ty_sz ty, ty_sz + 1)
    , (pokeBSNull domain_sz domain, domain_sz + 1)
    ]
  where
    name_sz = BS.length name
    ty_sz = BS.length ty
    domain_sz = BS.length domain

data RecvAllResult = RecvAllOK | RecvAllClosed

recvAll :: S.Socket -> Ptr Word8 -> Int -> IO RecvAllResult
recvAll s = loop
  where
    loop ptr i = do
      cnt <- S.recvBuf s ptr i
      if cnt == i
        then return RecvAllOK
        else if cnt == 0
          then return RecvAllClosed
          else loop (plusPtr ptr cnt) (i - cnt)

sendAll :: S.Socket -> Ptr Word8 -> Int -> IO ()
sendAll s = loop
  where
    loop ptr' i' = do
      cnt <- S.sendBuf s ptr' i'
      if cnt == i'
        then return ()
        else loop (plusPtr ptr' cnt) (i' - cnt)

data SockEx = SockEx deriving (Show, Typeable)

instance Exception SockEx

sendThread :: S.Socket
           -> Chan AnyRequestRegistration
           -> AsyncConnectionErrorHandler
           -> MVar ThreadId
           -> MVar ThreadId
           -> (forall a. IO a -> IO a)
           -> IO ()
sendThread sock chan e_handler sTidVar rTidVar unmask = do
    _ <- (try :: IO () -> IO (Either SockEx ())) . unmask $ do
      myThreadId >>= putMVar sTidVar
      Left e <- (try loop) :: IO (Either IOError ())
      takeMVar rTidVar >>= flip throwTo SockEx
      _ <- forkIO . e_handler $ AsyncConnectionIOError e
      drain
    unmask drain
  where
    loop = do
      (AnyRequestRegistration ctx req them) <- readChan chan
      let sz = size req
          full_sz = ipcMsgHdrSz + sz
          op = operation req
      allocaBytes (full_sz + 1) $ \reqptr -> do
        pokeHdr (IpcMsgHdr (fromIntegral $ sz + 1) op ctx) reqptr
        poke (plusPtr reqptr ipcMsgHdrSz) (0 :: CChar)
        pokeBody req $ (plusPtr reqptr (ipcMsgHdrSz + 1))
        sendAll sock (castPtr reqptr) full_sz
        alloca $ \cmsgptr -> do
          poke cmsgptr (S.fdSocket them)
          cmsg <- unsafePackCStringLen (castPtr cmsgptr, #{size int})
          body <- unsafePackCStringLen ((plusPtr reqptr full_sz), 1)
          sendMsg sock body (S.SockAddrUnix "")
            [ CMsg #{const SOL_SOCKET} #{const SCM_RIGHTS} cmsg ]
          S.close them
      loop

    drain = do
      (AnyRequestRegistration _ _ them) <- readChan chan
      S.close them
      drain

class PeekableResponse a where
  peekResponseBody :: Ptr a -> Int -> IO (Maybe a)

instance PeekableResponse NTDResponse where
  peekResponseBody buf sz = runMaybeT $ do
    name_null <- findNull (castPtr buf) sz
    name <- lift $ packCStringLen (castPtr buf, name_null)
    let buf' = plusPtr buf (name_null + 1)
        sz' = sz - (name_null + 1)
    regtype_null <- findNull buf' sz'
    regtype <- lift $ packCStringLen (buf', regtype_null)
    let buf'' = plusPtr buf' (regtype_null + 1)
        sz'' = sz' - (regtype_null + 1)
    domain_null <- findNull buf'' sz''
    domain <- lift $ packCStringLen (buf'', domain_null)
    return $ NTDResponse name regtype domain

instance PeekableResponse ResolveResponse where
  peekResponseBody buf sz = runMaybeT $ do
    name_null <- findNull (castPtr buf) sz
    name <- lift $ packCStringLen (castPtr buf, name_null)
    let buf' = plusPtr buf (name_null + 1)
        sz' = sz - (name_null + 1)
    target_null <- findNull buf' sz'
    target <- lift $ packCStringLen (buf', target_null)
    let buf'' = plusPtr buf' (target_null + 1)
        sz'' = sz' - (target_null + 1)
        port_sz = sizeOf (undefined :: S.PortNumber)
    when (sz'' < port_sz) mzero
    port <- lift $ peek buf''
    let buf''' = plusPtr buf'' port_sz
        sz''' = sz'' - port_sz
        len_sz = 2 -- uint16
    when (sz''' < len_sz) mzero
    len <- (lift $ fromBigEndian <$> peek buf''') :: MaybeT IO Word16
    let buf'''' = plusPtr buf''' len_sz
        sz'''' = sz''' - len_sz
        len' = fromIntegral len
    when (sz'''' < len') mzero
    txt <- lift $ packCStringLen (buf'''', len')
    return $ ResolveResponse name target port txt

findNull :: CString -> Int -> MaybeT IO Int
findNull = go 0
  where
    go _ _ 0 = mzero
    go acc ptr n = do
      c <- lift $ peek ptr :: MaybeT IO CChar
      case c of
        0 -> return acc
        _ -> go (acc + 1) (plusPtr ptr 1) (n - 1)

-- TODO: We should buffer reads here.
recvThread :: S.Socket
           -> CM.Map Word64 AnyAsyncResponseHandler
           -> AsyncConnectionErrorHandler
           -> MVar ThreadId
           -> MVar ThreadId
           -> (forall a. IO a -> IO a)
           -> IO ()
recvThread sock handlers e_handler sTidVar rTidVar unmask = do
    _ <- (try :: IO () -> IO (Either SockEx ())) $ do
      myThreadId >>= putMVar rTidVar
      err <- try $ do
        Left ex <- try $ unmask loop
        return ex
      readMVar sTidVar >>= flip throwTo SockEx
      -- After here we can't get a SockEx from the send thread
      unmask $ do
        _ <- forkIO . e_handler $ case err of
          Left e -> AsyncConnectionIOError e
          Right e -> e
        drain
    unmask drain
  where
    loop = do
      hdr <- allocaBytes ipcMsgHdrSz $ \buf -> do
        res <- recvAll sock (castPtr buf) ipcMsgHdrSz
        case res of
          RecvAllClosed -> throwIO AsyncConnectionClosedError
          RecvAllOK -> peekHdr buf
      m_handler <- CM.lookup (context hdr) handlers
      let len = fromIntegral $ datalen hdr
      allocaBytes len $ \buf -> do
        res <- recvAll sock buf len
        case res of
          RecvAllClosed -> throwIO AsyncConnectionClosedError
          RecvAllOK -> return ()
        case m_handler of
          Nothing -> return ()
          Just (AnyAsyncResponseHandler handler) -> do
            e_r_hdr <- peekResponseHeader buf len
            case e_r_hdr of
              Left err -> void . forkIO . handler $ Left err
              Right r_hdr -> do
                m_r_body <- peekResponseBody
                  (plusPtr buf responseHdrSz)
                  (len - responseHdrSz)
                let response = case m_r_body of
                      Just r_body -> Right $ Response r_hdr r_body
                      Nothing -> Left $ kDNSServiceErr_ShortResponse
                void . forkIO $ handler response
      loop

    drain = do
      entries <- CM.unsafeToList handlers
      mapM_ (\(ctx, _) -> CM.delete ctx handlers) entries
      -- This is ugly, but this is also an unlikely error path...
      threadDelay 5000
      drain

    responseHdrSz =
      #{size DNSServiceFlags} +
      4 + -- interface index
      #{size DNSServiceErrorType}

    peekResponseHeader buf len = if len < responseHdrSz
      then return $ Left kDNSServiceErr_ShortResponse
      else do
      flags <- DNSServiceFlags . fromBigEndian <$> peek (castPtr buf)
      ifi <- InterfaceIndex . fromBigEndian <$>
        peek (plusPtr buf #{size DNSServiceFlags})
      err <- DNSServiceErrorType . fromBigEndian <$>
        peek (plusPtr buf (#{size DNSServiceFlags} + 4))
      return $ case err of
        DNSServiceErrorType #{const kDNSServiceErr_NoError} ->
          Right (ResponseHeader flags ifi)
        _ -> Left err
