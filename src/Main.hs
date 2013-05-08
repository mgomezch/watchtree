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
  , RankNTypes
  , RecordWildCards
  , TemplateHaskell
  , TypeFamilies
  , UnicodeSyntax
  #-}

import Control.Arrow                   ((&&&))
import Control.Concurrent.Chan.Lifted  (newChan, readChan)
import Control.Monad                   (forM_, forever, mapM, void, when)
import Control.Monad.Logger            (runNoLoggingT, runStderrLoggingT, logDebug, logError, logInfo)
import Control.Monad.IO.Class          (liftIO)
import Control.Monad.Trans.Resource    (allocate, runResourceT)
import Crypto.Conduit                  (hashFile)
import Crypto.Hash.CryptoAPI           (SHA1)
import Data.Aeson.TH                   (deriveJSON)
import Data.Bool                       (Bool(True, False))
import Data.ByteString                 (ByteString)
import Data.ByteString.Char8           (readFile)
import Data.Data                       (Data)
import Data.Either                     (Either(Left, Right))
import Data.Function                   (($), flip, id)
import Data.Function.Unicode           ((∘))
import Data.Functor                    ((<$>))
import Data.List                       (concat)
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
import System.IO                       (print, FilePath, IO)
import System.IO.Error                 (tryIOError)
import System.Process                  (runCommand)
import Text.Regex.TDFA                 ((=~))
import Text.Regex.TDFA.String          ()
import Text.Show                       (Show, show)
import Text.Shakespeare.Text           (st)

import qualified System.Console.CmdArgs.Implicit as C (name)



data Args = Args
  { root, patternFile, databaseFile ∷ FilePath
  , verbose ∷ Bool
  }
  deriving (Data, Show, Typeable)

cmdArgsQuote [d|
  runArgs = cmdArgs# args :: IO Args
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
  path String
  hash ByteString
  timestamp UTCTime
  UniqueFile path hash
  deriving Show
|]

data Rules = Rules { rules :: [Rule] }
data Rule = Rule { name, pattern, command :: String }
concat <$> mapM (deriveJSON id) [''Rules, ''Rule]

eventNew ∷ ActionPredicate
eventNew event = case event of
  Added    {} → True
  Modified {} → True
  _           → False

main ∷ IO ()
main = do
  Args {..} ← runArgs
  events ← newChan
  runResourceT ∘ runStderrLoggingT $ do
    eitherRules ← liftIO $ decodeEither <$> readFile patternFile
    case eitherRules of
      Left e → $logError $ pack e
      Right rs → do
        (_, manager) ← allocate startManager stopManager
        liftIO $ watchTreeChan manager (fromString root) eventNew events
        withSqliteConn (pack databaseFile) $ \ connection → do
          runNoLoggingT $ flip runSqlConn connection $ runMigration migrateAll
          forever $ do
            event ← readChan events
            when verbose $ $logDebug ∘ pack $ show event
            let (filePath, fileTimestamp) = (encodeString ∘ eventPath) &&& eventTime $ event
            hash ← liftIO ∘ tryIOError $ encode <$> (hashFile filePath ∷ IO SHA1)
            case hash of
              Left e → when verbose $ $logInfo ∘ pack $ show e
              Right fileHash → do
                result ← runNoLoggingT $ flip runSqlConn connection $ insertBy $ File {..}
                case result of
                  Left duplicate → when verbose $ $logInfo [st|Duplicate file “#{show duplicate}” from event “#{show event}”|]
                  Right key → do
                    when verbose $ $logInfo [st|Inserted event “#{show event}” into key “#{show key}”|]
                    forM_ (rules rs) $ \ Rule {..} → do
                      liftIO $ print filePath
                      liftIO $ print pattern
                      when (filePath =~ pattern) $ do
                        when verbose $ $logInfo [st|Event “#{show event}” triggered rule “#{name}”|]
                        void ∘ liftIO $ runCommand command
