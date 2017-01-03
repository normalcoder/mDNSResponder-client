{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module Test (tests) where

import Data.Maybe
import Control.Concurrent
import Control.Monad

import Data.ByteString

import Distribution.TestSuite

import Network.DNS.MDNSResponder.Client

handle_err :: MVar (Maybe String) -> AsyncConnectionErrorHandler
handle_err var err = putMVar var . Just $
  "connect async: " ++ (show err)

register_req :: Request NTDResponse
register_req = ServiceRegister
  mempty
  kDNSServiceInterfaceIndexLocalOnly
  empty
  "_test._tcp"
  empty
  empty
  80
  empty

browse_req :: Request NTDResponse
browse_req = ServiceBrowse
  kDNSServiceInterfaceIndexLocalOnly
  "_test._tcp"
  empty

resolve_req :: NullFreeByteString
            -> NullFreeByteString
            -> NullFreeByteString
            -> Request ResolveResponse
resolve_req = ServiceResolve
  mempty
  kDNSServiceInterfaceIndexLocalOnly

handle_register_res :: MVar (Maybe String) -> AsyncResponseHandler a
handle_register_res var (Left err) = putMVar var . Just $
  "register async: " ++ (show err)
handle_register_res var (Right _) = putMVar var Nothing

handle_browse_res :: MVar (Either String (Response a))
                  -> AsyncResponseHandler a
handle_browse_res var (Left err) = putMVar var . Left $
  "browse async: " ++ (show err)
handle_browse_res var (Right res) = putMVar var $ Right res

handle_resolve_res :: MVar (Maybe String) -> AsyncResponseHandler a
handle_resolve_res var (Left err) = putMVar var . Just $
  "resolve async: " ++ (show err)
handle_resolve_res var (Right _) = putMVar var Nothing

resolve :: IO ()
        -> Connection
        -> Response NTDResponse
        -> MVar (Either String a)
        -> IO Progress
resolve cleanup' con (Response _ (NTDResponse {..})) var' = do
  var <- newEmptyMVar
  tid <- forkIO $ do
    Left str <- takeMVar var'
    putMVar var $ Just str
  let cleanup = do
        killThread tid
        cleanup'
      req = resolve_req ntd_name ntd_regtype ntd_domain
  err <- request con req (handle_resolve_res var)
  when (err /= kDNSServiceErr_NoError) $
    putMVar var . Just $ "resolve sync: " ++ (show err)
  res <- takeMVar var
  case res of
    Just msg -> do
      cleanup
      return . Finished $ Fail msg
    Nothing -> return $ Finished Pass

browseThen :: IO ()
           -> Connection
           -> MVar (Maybe String)
           -> IO Progress
browseThen cleanup' con var' = do
  var <- newEmptyMVar
  tid <- forkIO $ takeMVar var' >>= putMVar var . Left . fromJust
  let cleanup = do
        killThread tid
        cleanup'
  err <- request con browse_req (handle_browse_res var)
  when (err /= kDNSServiceErr_NoError) $
    putMVar var . Left $ "browse sync: " ++ (show err)
  res <- takeMVar var
  case res of
    Left msg -> do
      cleanup
      return . Finished $ Fail msg
    Right res' -> return $
      Progress "browse" (resolve cleanup con res' var)

registerThen :: IO ()
             -> Connection
             -> MVar (Maybe String)
             -> IO Progress
registerThen cleanup con var = do
  err <- request con register_req (handle_register_res var)
  when (err /= kDNSServiceErr_NoError) $
    putMVar var . Just $ "register sync: " ++ (show err)
  res <- takeMVar var
  case res of
    Just msg -> do
      cleanup
      return . Finished $ Fail msg
    Nothing -> return $
      Progress "register" (browseThen cleanup con var)

connectThen :: IO Progress
connectThen = do
  var <- newEmptyMVar
  addr <- defaultAddr
  e_con <- connect addr (handle_err var)
  return $ case e_con of
    Left err -> Finished . Fail $ "connect: " ++ (show err)
    Right con ->
      Progress "connect" (registerThen (disconnect con) con var)

tests :: IO [Test]
tests = return [ (Test registerAndResolve) ]
  where
    registerAndResolve = TestInstance
      { run = connectThen
      , name = "Register and resolve a service"
      , tags = []
      , options = []
      , setOption = \_ _ -> Right registerAndResolve
      }
