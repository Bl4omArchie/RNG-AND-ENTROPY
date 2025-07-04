from PIL import Image
import cv2


def stream_camera():
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("Error: Could not open camera.")
        return

    while cv2.waitKey(1) != ord('q'):
        ret, frame = cap.read()
        if not ret:
            print("Error: Cannot receive frame (stream end?). Exiting...")
            break

        frame_bytes = frame.tobytes()
        print (frame_bytes)


    cap.release() 
    cv2.destroyAllWindows()


def test():
    cap = cv2.VideoCapture(0)
    scaling_factor = 1

    while True:
        ret, frame = cap.read()
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2BGRA)
        cv2.imwrite('capture.jpg', frame)

        input_image = Image.open("capture.jpg")
        width, height = input_image.size
        
        for i in range(2):
            for j in range(2):
                print (input_image.getpixel((i, j)))
                print ("\n")

        print (rgb[0][0])

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    stream_camera()