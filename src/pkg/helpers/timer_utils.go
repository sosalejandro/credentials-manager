package helpers

import (
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"github.com/sosalejandro/credentials/src/pkg/password"
	"github.com/sosalejandro/timer"
)

// CheckTimer checks if the timer is blocked
func CheckTimer(timer *timer.TimerManager) (ok bool, err error) {
	ok, err = timer.IsTimerBlocked()

	if err != nil {
		return
	}

	if ok {
		return ok, exceptions.ErrTimerBlocked
	}

	return
}

// UnblockTimer unblock the timer
func UnblockTimer(mk string, cmk *password.EncryptedPassword, timer *timer.TimerManager) (err error) {
	// check mk is correct and unblock timer
	if ok := cmk.VerifyPassword(mk); !ok {
		return exceptions.ErrInvalidMasterKey
	}

	err = timer.ResetTimer()

	return
}
