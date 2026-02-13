import java.util.ArrayDeque;
import java.util.Deque;

public class Stack {

    private final Deque<String> stack;

    public Stack() {
        this.stack = new ArrayDeque<>();
    }

    public void push(String value) {
        stack.push(value);
    }

    public String pop() {
        if (stack.isEmpty()) {
            throw new IllegalStateException("Stack vacío");
        }
        return stack.pop();
    }

    public String peek() {
        if (stack.isEmpty()) {
            throw new IllegalStateException("Stack vacío");
        }
        return stack.peek();
    }

    public int size() {
        return stack.size();
    }

    public boolean isEmpty() {
        return stack.isEmpty();
    }

    public void clear() {
        stack.clear();
    }

    @Override
    public String toString() {
        return stack.toString();
    }
}
