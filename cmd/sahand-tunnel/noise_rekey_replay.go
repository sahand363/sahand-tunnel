// Initiates an explicit in-band `REKEY_INIT -> REKEY_ACK -> REKEY_COMMIT` exchange
// and waits up to `timeout` for the epoch transition to complete.
// Works both when another goroutine is concurrently reading from `ntc` and when `ntc` is idle.
func (ntc *noiseTransportConn) Rekey(timeout time.Duration) error {
	if ntc.closed.Load() {
		return net.ErrClosed
	}
	if timeout <= 0 {
		timeout = noiseDefaultRekeyWait
	}

	doneCh, payload, err := ntc.beginRekeyInit()
	if err != nil {
		return err
	}

	if err := ntc.WriteFrame(noiseFrameTypeRekeyInit, payload); err != nil {
		_ = ntc.Close()
		return err
	}

	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Drive ReadFrame in a helper goroutine in case no application goroutine is currently calling Read().
	// Any application data frame encountered while waiting for REKEY_ACK is buffered into ntc.readBuf.
	go func() {
		for time.Now().Before(deadline) {
			select {
			case <-doneCh:
				return
			default:
			}
			fType, plain, rErr := ntc.ReadFrame()
			if rErr != nil {
				return
			}
			if fType == noiseFrameTypeData && len(plain) > 0 {
				ntc.bufMu.Lock()
				ntc.readBuf.Write(plain)
				ntc.bufMu.Unlock()
			}
		}
	}()

	select {
	case rErr := <-doneCh:
		if rErr != nil {
			_ = ntc.Close()
			return rErr
		}
		return nil
	case <-timer.C:
		_ = ntc.Close()
		return errors.New("noise transport rekey timed out")
	}
}
