import numpy as np
import base64
import io
import hashlib
import zlib
import struct
import subprocess
import tempfile
import os
from scipy.io import wavfile

# --- КОНСТАНТЫ PCP (MFSK) ---
PCP_SAMPLE_RATE = 8000
PCP_CHUNK_MS = 60
PCP_BITS = 4
PCP_FREQS = np.linspace(1000, 2600, 2**PCP_BITS)
PCP_AMP = 16000
PCP_SAMPLES_PER_CHUNK = int(PCP_SAMPLE_RATE * PCP_CHUNK_MS / 1000)
PCP_TIME = np.linspace(0., PCP_CHUNK_MS / 1000, PCP_SAMPLES_PER_CHUNK)

class AudioProcessor:
    
    @staticmethod
    def convert_to_wav_pcm(input_bytes: bytes) -> tuple[int, np.ndarray]:
        """
        Универсальный конвертер любого аудио в WAV PCM 16-bit через FFMPEG.
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp_in:
            tmp_in.write(input_bytes)
            tmp_in_name = tmp_in.name
        
        tmp_out_name = tmp_in_name + ".wav"
        
        try:
            subprocess.run(
                ["ffmpeg", "-y", "-i", tmp_in_name, "-ac", "1", "-ar", "44100", "-f", "wav", tmp_out_name],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            rate, data = wavfile.read(tmp_out_name)
            if len(data.shape) > 1: data = data[:, 0]
            return rate, data.astype(np.int16)
        except Exception as e:
            print(f"FFMPEG Error: {e}")
            return 0, np.array([])
        finally:
            if os.path.exists(tmp_in_name): os.remove(tmp_in_name)
            if os.path.exists(tmp_out_name): os.remove(tmp_out_name)

    @staticmethod
    def scramble_audio(audio_bytes: bytes, key_bytes: bytes, is_encrypt: bool = True) -> bytes:
        """GVP: Скремблирование (Инверсия спектра + Frequency Hopping)."""
        try:
            if is_encrypt:
                rate, data = AudioProcessor.convert_to_wav_pcm(audio_bytes)
                if rate == 0: return b""
            else:
                try:
                    with io.BytesIO(audio_bytes) as bio:
                        rate, data = wavfile.read(bio)
                except: return b""

            window_size = 1024
            pad_len = window_size - (len(data) % window_size)
            if pad_len != window_size:
                data = np.pad(data, (0, pad_len), mode='constant')
            
            signal = data.astype(np.float32) / 32768.0
            seed = int(hashlib.sha256(key_bytes).hexdigest(), 16) % (2**32)
            rng = np.random.default_rng(seed)
            processed_signal = np.zeros_like(signal)

            for i in range(0, len(signal), window_size):
                chunk = signal[i:i+window_size]
                spectrum = np.fft.rfft(chunk)
                coeffs = spectrum[1:]
                num_bands = 16
                band_size = len(coeffs) // num_bands
                perm = rng.permutation(num_bands)
                new_coeffs = np.zeros_like(coeffs)
                
                if is_encrypt:
                    for src_idx, dst_idx in enumerate(perm):
                        band = coeffs[src_idx*band_size : (src_idx+1)*band_size]
                        if src_idx % 2 == 0: band = np.flip(band)
                        new_coeffs[dst_idx*band_size : (dst_idx+1)*band_size] = band
                else:
                    inv_perm = np.argsort(perm)
                    for dst_idx, src_idx in enumerate(inv_perm):
                        band = coeffs[dst_idx*band_size : (dst_idx+1)*band_size]
                        if src_idx % 2 == 0: band = np.flip(band)
                        new_coeffs[src_idx*band_size : (src_idx+1)*band_size] = band

                spectrum[1:] = new_coeffs
                processed_signal[i:i+window_size] = np.fft.irfft(spectrum)

            out_int16 = (processed_signal * 32767).astype(np.int16)
            out_bio = io.BytesIO()
            wavfile.write(out_bio, rate, out_int16)
            return out_bio.getvalue()
        except Exception as e:
            print(f"DSP GVP Error: {e}")
            return b""

    # --- PCP ЛОГИКА (MFSK) ---

    @staticmethod
    def generate_pcp_audio(text: str) -> bytes:
        """PCP: Кодирование текста в MFSK аудио."""
        try:
            data = text.encode('utf-8')
            crc = zlib.crc32(data)
            payload = struct.pack('!I', len(data)) + data + struct.pack('!I', crc)
            
            bit_string = ''.join(format(byte, '08b') for byte in payload)
            if len(bit_string) % PCP_BITS != 0:
                padding = PCP_BITS - (len(bit_string) % PCP_BITS)
                bit_string += '0' * padding

            pcm_signal = np.array([], dtype=np.float64)
            for i in range(0, len(bit_string), PCP_BITS):
                chunk_bits = bit_string[i:i+PCP_BITS]
                freq_index = int(chunk_bits, 2)
                frequency = PCP_FREQS[freq_index]
                tone = PCP_AMP * np.sin(2 * np.pi * frequency * PCP_TIME)
                pcm_signal = np.concatenate([pcm_signal, tone])

            out_int16 = pcm_signal.astype(np.int16)
            out_bio = io.BytesIO()
            wavfile.write(out_bio, PCP_SAMPLE_RATE, out_int16)
            return out_bio.getvalue()
        except Exception as e:
            print(f"DSP PCP Encode Error: {e}")
            return b""

    @staticmethod
    def decode_pcp_audio(audio_bytes: bytes) -> str:
        """
        PCP: Декодирование MFSK аудио обратно в текст (FFT).
        """
        try:
            # 1. Читаем WAV из байтов
            with io.BytesIO(audio_bytes) as bio:
                rate, signal = wavfile.read(bio)
            
            if rate != PCP_SAMPLE_RATE:
                print(f"PCP Decode Error: Wrong sample rate {rate}, expected {PCP_SAMPLE_RATE}")
                return ""

            # 2. Логика декодирования (из твоего скрипта)
            bit_string = ""
            num_chunks = len(signal) // PCP_SAMPLES_PER_CHUNK
            
            for i in range(num_chunks):
                chunk_signal = signal[i*PCP_SAMPLES_PER_CHUNK : (i+1)*PCP_SAMPLES_PER_CHUNK]
                
                fft_result = np.fft.fft(chunk_signal)
                fft_freqs = np.fft.fftfreq(len(chunk_signal), 1/PCP_SAMPLE_RATE)
                
                # Ищем пик в первой половине спектра
                peak_index = np.argmax(np.abs(fft_result[:len(fft_result)//2]))
                dominant_freq = fft_freqs[peak_index]
                
                # Ищем ближайшую частоту
                closest_freq_index = np.argmin(np.abs(PCP_FREQS - dominant_freq))
                bit_string += format(closest_freq_index, f'0{PCP_BITS}b')

            # 3. Биты -> Байты
            all_bytes = bytearray()
            for i in range(0, len(bit_string), 8):
                byte_str = bit_string[i:i+8]
                if len(byte_str) < 8: break
                all_bytes.append(int(byte_str, 2))
            
            # 4. Распаковка и CRC
            try:
                original_len = struct.unpack('!I', all_bytes[0:4])[0]
                data_end = 4 + original_len
                data = all_bytes[4:data_end]
                received_crc = struct.unpack('!I', all_bytes[data_end:data_end+4])[0]
            except:
                print("PCP Decode: Struct unpack failed")
                return ""

            calculated_crc = zlib.crc32(data)
            if received_crc != calculated_crc:
                print(f"PCP Decode: CRC Mismatch! {received_crc} != {calculated_crc}")
                return "" # Или вернуть то что есть с пометкой [CORRUPTED]

            return data.decode('utf-8')

        except Exception as e:
            print(f"DSP PCP Decode Error: {e}")
            return ""