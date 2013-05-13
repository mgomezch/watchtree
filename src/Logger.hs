{-# LANGUAGE
    FlexibleInstances
  , NoImplicitPrelude
  , QuasiQuotes
  , TemplateHaskell
  , TypeSynonymInstances
  , UnicodeSyntax
  #-}

module Logger (log) where

import Control.Monad              (when)
import Control.Monad.Logger       (liftLoc, monadLoggerLog)
import Control.Monad.Unicode      ((≫=))
import Data.Function              (($))
import Data.Function.Unicode      ((∘))
import Data.Maybe                 (Maybe(Just, Nothing))
import Language.Haskell.TH.Lib    (ExpQ, appE, infixE, varE)
import Language.Haskell.TH.Syntax (lift, mkName, qLocation)

compose ∷ (β → γ) → (α → β) → α → γ
compose = (∘)

log ∷ ExpQ
log
  = varE 'compose
  ! infixE
    (Just $ varE 'when ! varE (mkName "verbose"))
    (varE 'compose)
    Nothing
  ! [|monadLoggerLog $(qLocation ≫= liftLoc) $(lift "watchtree")|]
  where
    infixl 1 !
    (!) = appE
