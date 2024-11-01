package analizador_lexico_definitivo2;
/**
 *
 * @author frida
 */
public class Nodo {
    String valor;
    Nodo der;
    Nodo izq;

    public Nodo(String valor) {
        this.valor = valor;
        this.der = null;
        this.izq = null;
    }   
}
