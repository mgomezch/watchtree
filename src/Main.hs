{-# OPTIONS_GHC
    -fno-warn-missing-fields
    -fno-warn-missing-signatures
    -fno-warn-unused-binds
  #-}

{-# LANGUAGE
    DeriveDataTypeable
  , FlexibleContexts
  , GADTs
  , MagicHash
  , NoImplicitPrelude
  , NoMonomorphismRestriction
  , OverloadedStrings
  , QuasiQuotes
  , RecordWildCards
  , TemplateHaskell
  , TypeFamilies
  , UnicodeSyntax
  #-}

import Control.Arrow                   ((&&&))
import Control.Concurrent.Chan.Lifted  (newChan, readChan)
import Control.Monad                   (Monad, forM_, forever, mapM, return, void, when)
import Control.Monad.Error.Class       (catchError, throwError)
import Control.Monad.IO.Class          (liftIO)
import Control.Monad.Logger            (LogLevel(LevelDebug, LevelError, LevelInfo), runNoLoggingT, runStderrLoggingT)
import Control.Monad.Trans.Error       (noMsg, runErrorT)
import Control.Monad.Trans.Resource    (allocate, runResourceT)
import Control.Monad.Unicode           ((≫=), (≫))
import Crypto.Conduit                  (hashFile)
import Crypto.Hash.CryptoAPI           (SHA1)
import Data.Aeson.TH                   (deriveJSON)
import Data.Bool                       (Bool(True, False))
import Data.ByteString                 (ByteString)
import Data.ByteString.Char8           (readFile, unpack)
import Data.Data                       (Data)
import Data.Either                     (either)
import Data.Function                   (($), flip, id)
import Data.Function.Unicode           ((∘))
import Data.Functor                    ((<$>), Functor)
import Data.List                       (concat)
import Data.Maybe                      (Maybe(Just))
import Data.Serialize                  (encode)
import Data.String                     (String, fromString)
import Data.Text                       (pack)
import Data.Time                       (UTCTime)
import Data.Typeable                   (Typeable)
import Data.Yaml                       (decodeEither)
import Database.Persist                (insertBy)
import Database.Persist.Sqlite         (runMigration, runSqlConn, withSqliteConn)
import Database.Persist.TH             (mkMigrate, mkPersist, persistUpperCase, share, sqlSettings)
import Filesystem.Path.CurrentOS       (encodeString)
import System.Console.CmdArgs.Implicit (help, ignore, helpArg, program, summary, versionArg)
import System.Console.CmdArgs.Quote    ((&=#), cmdArgs#, cmdArgsQuote)
import System.FSNotify                 (ActionPredicate, Event(Added, Modified), eventTime, eventPath, startManager, stopManager, watchTreeChan)
import System.IO                       (FilePath, IO)
import System.IO.Error                 (tryIOError)
import System.Process                  (createProcess, env, shell)
import Text.Regex.TDFA                 ((=~))
import Text.Regex.TDFA.String          ()
import Text.Shakespeare.Text           (st)
import Text.Show                       (Show, show)

import qualified Data.ByteString.Base16          as B16 (encode)
import qualified System.Console.CmdArgs.Implicit as C   (name)

import Logger (log)



data Args = Args
  { root, patternFile, databaseFile ∷ FilePath
  , verbose ∷ Bool
  }
  deriving (Data, Typeable)

cmdArgsQuote [d|
  runArgs = cmdArgs# args ∷ IO Args
  args
    = Args
      { root         = "."              &=# C.name "r" &=# help "[current directory] root path to monitor for events"
      , patternFile  = "watchtree.yaml" &=# C.name "p" &=# help "[watchtree.yaml] YAML file with patterns and commands"
      , databaseFile = "watchtree.db"   &=# C.name "d" &=# help "[watchtree.db] SQLite database filename"
      , verbose      = False            &=# C.name "v" &=# help "[disabled] enable verbose output on standard error"
      }
    &=# program "watchtree"
    &=# summary "Run commands in response to directory tree modifications"
    &=# helpArg [help "Show this help message"]
    &=# versionArg [ignore]
  |]



share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistUpperCase|
File
  path      String
  hash      ByteString
  timestamp UTCTime

  UniqueFile path hash
  deriving Show
|]

data Rules = Rules { rules ∷ [Rule] }
data Rule = Rule { name, pattern, command ∷ String }
concat <$> mapM (deriveJSON id) [''Rules, ''Rule]

eventNew ∷ ActionPredicate
eventNew event = case event of
  Added    {} → True
  Modified {} → True
  _           → False



main ∷ IO ()
main = do
  let
    runWatcher
      = runResourceT
      ∘ runStderrLoggingT
      ∘ (≫= either (void ∘ return ∷ (Functor m, Monad m) ⇒ String → m ()) return)
      ∘ runErrorT

    withLogger logger = (≫= either ((≫ throwError noMsg) ∘ logger) return)

  Args {..} ← runArgs
  events ← newChan
  runWatcher $ do
    rs ← withLogger ($log LevelError) $ liftIO (decodeEither <$> readFile patternFile)
    (_, manager) ← allocate startManager stopManager
    liftIO $ watchTreeChan manager (fromString root) eventNew events
    withSqliteConn (pack databaseFile) $ \ connection → do
      runNoLoggingT ∘ flip runSqlConn connection $ runMigration migrateAll
      forever ∘ flip catchError (void ∘ return) $ do
        event ← readChan events
        $log LevelDebug $ show event
        let (filePath, fileTimestamp) = (encodeString ∘ eventPath) &&& eventTime $ event
        fileHash ← withLogger ($log LevelInfo ∘ show) $ liftIO ∘ tryIOError $ encode <$> (hashFile filePath ∷ IO SHA1)
        key ← withLogger
          (\ duplicate → $log LevelInfo [st|Duplicate file “#{show duplicate}” from event “#{show event}”|])
          $ runNoLoggingT ∘ flip runSqlConn connection ∘ insertBy $ File {..}
        $log LevelInfo [st|Inserted into key “#{show key}” data from event “#{show event}”|]
        forM_ (rules rs) $ \ Rule {..} → when (filePath =~ pattern) $ do
          $log LevelInfo [st|Event “#{show event}” triggered rule “#{name}”|]
          let
            commandEnvironment =
              [ ("WATCHTREE_EVENT_TIMESTAMP", show eventTime              )
              , ("WATCHTREE_EVENT_PATH"     , filePath                    )
              , ("WATCHTREE_EVENT_HASH"     , unpack $ B16.encode fileHash)
              ]
          void ∘ liftIO ∘ createProcess $ (shell command) { env = Just commandEnvironment }
