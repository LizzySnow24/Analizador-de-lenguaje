package analizador_lexico_definitivo2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FRIDA ELIZABETH GONZÁLEZ GARCÍA. 21630236
 */
public class Analizador_Lexico_Definitivo {

    static String archivoEntrada = "src\\analizador_lexico_definitivo2\\ENTRADA.txt";
    static HashMap<String, String> tiposDeVariables = new HashMap<>();    //Tabla de simbolos 
    // static HashMap<Integer, String> TablaD = new HashMap<>();    //Tabla de erorres Dinamica
    static ArrayList<TDA> TablaD = new ArrayList<>();
    static Stack<TDA> pilaSem = new Stack<>(); //pila semantica para verificar paridad de etiquetas     

    //Expresiones Regulares para el analizador sintáctico y el semántico.    
    static Pattern vacio = Pattern.compile("");
    static Pattern op_aritmetico = Pattern.compile("(\\+|-|\\*|\\/|%|\\^)");
    static Pattern op_log = Pattern.compile("(\\|\\||&&)");
    static Pattern op_condicional = Pattern.compile("(<=|>=|<|>|!=|==)");  //ya      
    static Pattern op_condicionalper = Pattern.compile("(\\:\\:)");  //ya      
    static Pattern op_decremento = Pattern.compile("(\\+\\+|--)");   //ya     
    static Pattern numero_ent = Pattern.compile("([0-9]+)");   //ya     
    static Pattern espacio = Pattern.compile("((\\s)?)");  //ya               
    static Pattern tipodedato = Pattern.compile("(ent|cad|flot)"); //ya         
    static Pattern ID = Pattern.compile("\\| ([a-z]+) \\|");     //ya   
    static Pattern cadena = Pattern.compile("[^\"]*");        //ya
    static Pattern flotante = Pattern.compile("(" + numero_ent + "\\." + numero_ent + ")");   //ya     
    static Pattern constante = Pattern.compile("(" + "(\"" + cadena + "\")" + "|" + "(" + numero_ent + ")" + "|" + "(" + flotante + ")" + ")");//ya  
    static Pattern operando = Pattern.compile("(" + constante + "|" + ID + ")");
    static Pattern declarar = Pattern.compile(espacio + "(" + ID + ")" + " : " + tipodedato + " ;" + espacio);//ya       
    static Pattern declaracion = Pattern.compile(declarar + "*"); //ya     
    static Pattern imprimir = Pattern.compile(espacio + "sout " + "\\( " + operando + " \\)" + " ;" + espacio); //ya
    static Pattern leer = Pattern.compile(espacio + "leer " + ID + " ;" + espacio); //ya
    static Pattern condicion_per = Pattern.compile("(" + ID + " " + op_condicionalper + " " + "(" + ID + "|" + "(" + numero_ent + "|" + flotante + ")" + ")" + ")"); //ya
    static Pattern operacion = Pattern.compile(operando + "(" + " " + op_aritmetico + " " + operando + ")");
    static Pattern per = Pattern.compile(espacio + "per " + "\\( " + ID + " = " + "(" + numero_ent + "|" + flotante + "|" + ID + ")" + " ; " + condicion_per + " ; " + ID + " " + "(" + op_decremento + ")" + " \\)" + espacio); //ya
    static Pattern condicion = Pattern.compile("(" + operando + " " + op_condicional + " " + operando + ")");
    static Pattern condicion_compleja = Pattern.compile("(" + condicion + ")" + "( " + op_log + " " + condicion + ")*");
    static Pattern si = Pattern.compile(espacio + "si " + "\\( " + condicion_compleja + " \\)" + espacio);
    static Pattern mien = Pattern.compile(espacio + "mien " + "\\( " + condicion_compleja + " \\)" + espacio);
    static Pattern etiquetas = Pattern.compile(espacio + "(contrario|iniciodeclararvar|findeclararvar|finper|finsi|fincontrario|finmien)" + espacio);
    static Pattern asignacion = Pattern.compile(espacio + "(" + "(" + ID + " = " + operando + ")" + "|" + ID + " = " + operacion + ")" + " ;" + espacio);
    static Pattern sentencias = Pattern.compile("(" + imprimir + "|" + leer + "|" + per + "|" + si + "|" + mien + "|" + etiquetas + "|" + asignacion + ")");
    static Pattern programa = Pattern.compile(vacio+"|(" + espacio + "iniciodeclararvar" + espacio + ")" + "|" + declaracion + "|" + "(" + espacio + "findeclararvar" + espacio + ")" + "|" + sentencias);
    static Pattern cad = Pattern.compile("\"(.*?)\"");

    public static String Codigo(String archivoEntrada) throws IOException { //recibe la ruta del archivo
        StringBuilder contenido = new StringBuilder(); //hacemos un objeto para almacenar el contenido del archivo
        try (BufferedReader reader = new BufferedReader(new FileReader(archivoEntrada))) {
            String line;
            while ((line = reader.readLine()) != null) {
                contenido.append(line).append("\n");
            }
        }
        return contenido.toString();
    }

    public static HashMap<Integer, String> TablaE() {
        HashMap<Integer, String> TablaErrorE = new HashMap<>();
        TablaErrorE.put(1, "Elemento no reconocido");
        TablaErrorE.put(2, "Variable no declarada");
        TablaErrorE.put(3, "Símbolo no reconocido");
        TablaErrorE.put(4, "Error de Sintaxis");
        TablaErrorE.put(5, "Variable repetida");
        TablaErrorE.put(6, "Etiqueta de cierre sin una sentencia abierta ");
        TablaErrorE.put(7, "Falta etiqueta de cierre ");
        TablaErrorE.put(8, "Constante no coincide con tipo de dato");
        TablaErrorE.put(9, "Tipos de datos no coinciden");
        TablaErrorE.put(10, "Operación inválida");
        TablaErrorE.put(11, "Variable declarada fuera de bloque");

        return TablaErrorE;
    }

    public static void Analizar(String archivo) {
        String error_var = "";
        String palabras[] = {"contrario", "flot", "per", "si", "ent", "mien", "sout",
            "leer", "finsi",
            "finmien", "fincontrario", "cad", "finper", "iniciodeclararvar", "findeclararvar"};
        Pattern alfabeto = Pattern.compile("^[a-z0-9\\/\\|\\;=:\\s\\\"+<>\\-\\[\\]\\(\\)\\n\\!\\*\\^\\&\\.]+");
        Pattern salto = Pattern.compile("\n");
        Pattern variable = Pattern.compile("\\|\\s([a-z]+)\\s\\|");
        Pattern comentario = Pattern.compile("//.*|/\\*[\\s\\S]*?\\*/|/\\*\\*[\\s\\S]*?\\*/");
        Pattern mensaje = Pattern.compile("\"(.*?)\"");
        Pattern palabrasClave = Pattern.compile("\\b(" + String.join("|", palabras) + ")\\b");
        Pattern oplog_arit_cond = Pattern.compile("(::|<=|==|>=|<|>|!=|\\+|\\-|\\*|\\/|=|%|\\^|\\|\\||&&|!)");
        Pattern num = Pattern.compile("\\b\\d+(\\.\\d+)?\\b");
        Pattern sim = Pattern.compile("(\\.|;|:|\"|,|\\{|\\}|\\[|\\]|\\(|\\))");

        Matcher validar = Pattern.compile(
                String.join("|",
                        salto.pattern(),
                        variable.pattern(),
                        comentario.pattern(),
                        mensaje.pattern(),
                        palabrasClave.pattern(),
                        oplog_arit_cond.pattern(),
                        num.pattern(),
                        sim.pattern())
        ).matcher(archivo);

        int contLinea = 1;
        String var = "";
        int ultimo = 0;
        boolean guardarVar = false;        

        while (validar.find()) {
            String coincidencia = validar.group();
            int inicio = validar.start();
            int fin = validar.end();
            String error = "";
            //System.out.println("esto es lo que coincidio, " + coincidencia);
            if (inicio > ultimo) {
                error = archivo.substring(ultimo, inicio);
                String[] word = error.split("\\s+");
                for (String palabra : word) {
                    if (palabra.length() > 1) {
                        //marcar_error = true;                        
                        TablaD.add(new TDA(TablaE().get(1), contLinea));
                    } else {
                        // marcar_error = true;
                        if (palabra.length() == 1) {
                            //TablaD.add(new TDA(TablaE().get(3),contLinea));                          
                        }
                    }
                }
            }
            for (int j = 0; j < error.length(); j++) {
                char simbo = error.charAt(j);
                String simbolo = String.valueOf(simbo);
                if (!(simbolo.matches(alfabeto.pattern()))) {
                    //TablaD.put(contLinea, TablaE().get(3));
                    TablaD.add(new TDA(TablaE().get(3), contLinea));
                }
            }
            if (coincidencia.equals("iniciodeclararvar")) {
                guardarVar = true;
            }
            if (coincidencia.equals("findeclararvar")) {
                guardarVar = false;
            }
            if ((coincidencia.equals("ent") || coincidencia.equals("cad") || coincidencia.equals("flot")) && guardarVar == true) {
                if (!tiposDeVariables.containsKey(var)) {
                    tiposDeVariables.put(var, coincidencia);
                } else {
                    TablaD.add(new TDA(TablaE().get(5), contLinea));
                    //TablaD.put(contLinea, TablaE().get(5));
                }
            }
            if (coincidencia.matches(variable.pattern()) && guardarVar) {
                var = coincidencia;
            } else if (coincidencia.matches(salto.pattern())) {
                contLinea++;
            } else if (coincidencia.matches(comentario.pattern())) {
            } else if (coincidencia.matches(mensaje.pattern())) {
            } else if (coincidencia.matches(palabrasClave.pattern())) {
            } else if (coincidencia.matches(oplog_arit_cond.pattern())) {
            } else if (coincidencia.matches(num.pattern())) {
            } else if (coincidencia.matches(sim.pattern())) {
                if (coincidencia.equals(":") && guardarVar == false) {
                    //controlar_var.put(contLinea, TablaE().get(11));
                    TablaD.add(new TDA(TablaE().get(11), contLinea));
                }
            } else if (!(tiposDeVariables.containsKey(coincidencia))) {
                if (coincidencia.matches(variable.pattern())) {
                    error_var = coincidencia;
                   // controlar_var.put(contLinea, TablaE().get(2));
                   TablaD.add(new TDA(TablaE().get(2), contLinea));
                } else {
                    TablaD.add(new TDA(TablaE().get(1), contLinea));
                    //TablaD.put(contLinea, TablaE().get(1));
                }
            }
            ultimo = fin;
        }
        if (ultimo < archivo.length()) {
            TablaD.add(new TDA(TablaE().get(1), contLinea));
            //TablaD.put(contLinea, TablaE().get(1));
        }
  /*      for (int elemento : controlar_var.keySet()) {
            int linea = elemento;
            String valor = controlar_var.get(elemento);
            TablaD.add(new TDA(valor, linea));
        } */
        //controlar_var.forEach((key, value) -> System.out.println("linea: " + key + ", error: " + value));  
        //tiposDeVariables.forEach((key, value) -> System.out.println("Variable: " + key + ", Tipo de dato: " + value));           
    }

    public static String archivo_limpio() { //Método para limpiar archivo de entrada 
        String archivoLimpio = "";
        try {
            String codigo = Codigo(archivoEntrada);
            //Eliminamos comentarios
            String comentario = codigo.replaceAll("//.*", "");
            // Eliminar líneas en blanco vacías.
            String lineaVacia = comentario.replaceAll("(?m)^[ \t]*\r?\n", "");
            // Reemplazar múltiples espacios por un solo espacio
            archivoLimpio = lineaVacia.replaceAll("[ \t]+", " ");
        } catch (IOException e) {
            System.out.println(e);
        }
        return archivoLimpio;
    }

    public static void guardarSalida(String archivoSalida, String contenido) throws IOException { //
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(archivoSalida))) {
            writer.write(contenido);
        }
    }

    public static ArrayList<String> separarLinea(String archivo_sintactico) {
        ArrayList<String> codigo = new ArrayList<>();
        String[] lineas = archivo_sintactico.toString().split("\\n");
        for (String linea : lineas) {
            codigo.add(linea);
        }
        return codigo;
    }

    public static void Analizador_Sintactico(ArrayList<String> codigo, ArrayList<String> codigo_entrada) {
        //   String linea = "| k | : cad = \"hola\" ;";
        for (String linea : codigo) {
            if (!(linea.matches(programa.pattern()))) {
                //System.out.println("ERROR DE SINTAXIS: "+linea);
                String error = linea;
                int indice_linea = codigo_entrada.indexOf(error) + 1;
                TablaD.add(new TDA(TablaE().get(4), indice_linea));
                //TablaD.put((indice_linea + 1), TablaE().get(4));
                // System.out.println("ERROR DE SINTAXIS: " + error + " EN LA LINEA " + (indice_linea + 1));
            }
        }
        /*     if(linea.matches(declaracion.pattern())){
         System.out.println(linea);
     }    */
    }

    public static void Analizador_Semantico(ArrayList<String> codigo, ArrayList<String> codigo_entrada) {
        String ultima_etiqueta = "";
        Pattern no_si = Pattern.compile(espacio + "si (.*?)");
        Pattern no_per = Pattern.compile(espacio + "per (.*?)");
        Pattern no_mien = Pattern.compile(espacio + "mien (.*?)");
        Matcher match;

        Pattern etiquetasFin = Pattern.compile(espacio + "(findeclararvar|finper|finsi|fincontrario|finmien)" + espacio);
        for (String linea : codigo) {
            int indice_linea = (codigo_entrada.indexOf(linea)) + 1;
            if (linea.matches(no_si.pattern())) {
                pilaSem.add(new TDA("si", indice_linea));
            } else if (linea.matches(no_per.pattern())) {
                pilaSem.add(new TDA("per", indice_linea));
            } else if (linea.matches(no_mien.pattern())) {
                pilaSem.add(new TDA("mien", indice_linea));
            } else if (linea.matches("\\s*contrario\\s*")) {
                pilaSem.add(new TDA("contrario", indice_linea));
            } else if (linea.matches("\\s*iniciodeclararvar\\s*")) {
                pilaSem.add(new TDA("declararvar", indice_linea));
            } else if ((match = etiquetasFin.matcher(linea)).matches()) {
                ultima_etiqueta = match.group();
                if (!pilaSem.isEmpty()) { //si la pila no esta vacia, puede sacar elementos para comparar con las etiquetas de cierre                    
                    String elemento = pilaSem.pop().sentencia; //Saco el ultimo elemento de la pila                       
                    //si la etiqueta de cierre no coincide con la sentencia de la pila
                    if (!("fin" + elemento).equals(linea.trim())) {
                        TablaD.add(new TDA(TablaE().get(6), indice_linea));
                        //TablaD.put(indice_linea, TablaE().get(6));          
                    }
                } else {
                    TablaD.add(new TDA(TablaE().get(6), indice_linea));
                    //TablaD.put((indice_linea), TablaE().get(6)); //si hay una etiqueta de cierre pero la pila esta vacia, es porque no tiene sentencia          
                }
            }
        }
        //Validar Asignaciones de Datos en Declaracion      
        for (String linea : codigo) {
            int indice_linea = (codigo_entrada.indexOf(linea)) + 1;
            //expresiones
            if (linea.matches(si.pattern())) {
                VeriCondi(linea, indice_linea);
            } else if (linea.matches(mien.pattern())) {
                VeriCondi(linea, indice_linea);
            } else if (linea.matches(asignacion.pattern())) {
                EvaluarAsig(linea, indice_linea);
            } else if (linea.matches(per.pattern())) {
                per(linea, indice_linea);
            }
        }
        if (!pilaSem.isEmpty()) {
            for (TDA elem : pilaSem) {
                if (!(("fin" + (elem.sentencia)).equals(ultima_etiqueta.trim()))) {
                    //TablaD.put(elem.indice_linea, TablaE().get(7));          
                    TablaD.add(new TDA(TablaE().get(7), elem.indice_linea));
                }
            }
        }
    }

    public static void EvaluarAsig(String asig, int indice_linea) {
        //matchar operador, si es un + evaluar normalmente, sino, verificar si es un String (mandar error)
        HashMap<Integer, String> list_asig = new HashMap<>();//lista de operandos de las sentencias           
        int cont = 0, cont2 = 1;
        Matcher validar = Operandos(asig);
        while (validar.find()) {
            cont++;
            list_asig.put(cont, obtenerTipo(validar.group()));
        }
        if (cont == 2) {
            VeriCondi(asig, indice_linea);
        } else {
            String tipo1 = list_asig.get(1);
            if (tipo1 != null) {
                if (tipo1.equals("cad")) {
                    Matcher op_ari = op_aritmetico.matcher(asig);
                    while (op_ari.find()) {
                        if (!(op_ari.group().equals("+"))) {
                            //System.out.println(op_ari.group());
                            // TablaD.put(indice_linea, TablaE().get(10));
                            TablaD.add(new TDA(TablaE().get(10), indice_linea));
                        }
                    }
                }
            }
            // System.out.println("esto"+tipo1);
            // list_asig.forEach((key, value) -> System.out.println("Error: " + value + ", en la linea: " + key));
            while (cont2 < cont) {
                String tipo = list_asig.get(cont2 + 1);
                //System.out.println("tipo"+tipo);
                if (tipo1 != null) {
                    if (!(tipo1.equals(tipo))) {
                        //TablaD.put(indice_linea,TablaE().get(9));
                        TablaD.add(new TDA(TablaE().get(9), indice_linea));
                    }
                }
                cont2++;
            }
        }
    }

    public static Matcher Operandos(String sentencia) {
        Matcher validar = Pattern.compile(
                String.join("|",
                        ID.pattern(),
                        flotante.pattern(),
                        numero_ent.pattern(),
                        cad.pattern())
        ).matcher(sentencia);
        return validar;
    }

    public static void VeriCondi(String si, int indice_linea) {
        HashMap<Integer, String> list_oper = new HashMap<>();//lista de operandos de las sentencias
        int cont = 0, cont2 = 1;
        Matcher validar = Operandos(si);
        while (validar.find()) {
            cont++;
            list_oper.put(cont, obtenerTipo(validar.group()));
        }
        while (cont2 < cont) {
            String tipo1 = list_oper.get(cont2); //obtenemos el tipo de la variable 1           
            String tipo2 = list_oper.get(cont2 + 1);//obtenemos el tipo de la variable 2  
            cont2 = cont2 + 2;
            if (tipo1 != null) {
                if (!(tipo1.equals(tipo2))) {
                    //TablaD.put(indice_linea, TablaE().get(9));
                    TablaD.add(new TDA(TablaE().get(9), indice_linea));
                }
            }
        }
    }

    public static String obtenerTipo(String valor) {
        String dato = "";
        if (valor != null) {
            if (valor.matches(flotante.pattern())) {
                dato = "flot";
            } else if (valor.matches(cad.pattern())) {
                dato = "cad";
            } else if (valor.matches(numero_ent.pattern())) {
                dato = "ent";
            } else {
                String tipo_id = tiposDeVariables.get(valor);
                dato = tipo_id;
            }
        }
        return dato;
    }

    public static void per(String per, int indice_linea) {
        Matcher validar_oper = Operandos(per);
        while (validar_oper.find()) {
            String tipo = obtenerTipo(validar_oper.group());
            if (tipo != null) {
                if (!(tipo.equals("ent"))) {
                    TablaD.add(new TDA(TablaE().get(9), indice_linea));//TablaD.put(indice_linea, TablaE().get(9));          
                }
            }
        }
    }

    public static void Ensamblador(ArrayList<String> codigo) {
        ArrayList<String> codigo_ensamblador = new ArrayList<>();
        ArrayList<String> variables = new ArrayList<>();
        ArrayList<String> tokens_per = new ArrayList<>();
        ArrayList<String> var_leidas = new ArrayList<>();
        ArrayList<String> actualizadas = new ArrayList<>();
        boolean incremento = true;
        boolean flag_else = false;
        boolean flag_fin = false;
        String aux = "";
        int cont_si = 0;
        int contPer = 1;
        int salto = 0;
        int saltomien = 0;
        Matcher matcher;
        String id = "";
        int cont = 1;

        //Para saber cuantos si hay en total
        for (String linea : codigo) {
            if (linea.trim().matches(si.pattern())) {
                cont_si++;
            }
        }
        //System.out.println("total si: "+cont_si);

        codigo_ensamblador.add(".MODEL SMALL");
        codigo_ensamblador.add(".CODE");
        codigo_ensamblador.add("Inicio:");
        codigo_ensamblador.add("mov Ax, @Data");
        codigo_ensamblador.add("mov Ds, Ax\n");
        codigo_ensamblador.add("mov Ax, Ax\n");

        for (HashMap.Entry<String, String> var : tiposDeVariables.entrySet()) {
            id = var.getKey().replace("|", "");
            variables.add(id + " db 255, ?, 255 dup(\"$\")");
        }
        variables.add("salto00 db 10,13,10,13,\"$\"");

        for (String linea : codigo) {

            matcher = Operandos(linea);

            switch (Sentencia(linea)) {
                case "si":
                    ArrayList<String> lista_tokens = new ArrayList<>();
                    Pattern pattern1 = Pattern.compile(op_condicional.pattern());
                    Matcher op_cond = pattern1.matcher(linea);
                    String op_arit_cond = "";
                    int num_oper = 0;
                    while (matcher.find()) {
                        if (matcher.group().matches(ID.pattern())) {
                            lista_tokens.add(matcher.group(1)); //es mi ID sin los palitos
                        } else {
                            lista_tokens.add(matcher.group());
                        }
                    }
                    salto++;
                    codigo_ensamblador.add("Salto" + salto + ":");
                    salto++;
                    while (num_oper <= 1) {
                        if (lista_tokens.get(num_oper).matches("([a-z]+)")) { //caso para ID
                            if (actualizadas.contains(lista_tokens.get(num_oper))) {
                                codigo_ensamblador.add("mov Dx, offset " + lista_tokens.get(num_oper));
                            } else {
                                codigo_ensamblador.add("mov Dx, offset " + lista_tokens.get(num_oper) + " +2");
                            }
                        } else {
                            variables.add("Var" + cont + " db " + "'" + lista_tokens.get(num_oper) + "','$'"); //caso para constantes
                            codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                            cont++;
                        }
                        if (num_oper == 0) {
                            codigo_ensamblador.add("mov Si, Dx");
                            codigo_ensamblador.add("mov Cl, byte ptr [Si]\n ");
                        } else {
                            codigo_ensamblador.add("mov Si, Dx");
                            codigo_ensamblador.add("mov Ch, byte ptr [Si] \n");
                        }
                        num_oper++;
                    }

                    codigo_ensamblador.add("cmp Cl,Ch\n");

                    while (op_cond.find()) {
                        op_arit_cond = op_cond.group(); // el ultimo operador condicional                                                     
                    }

                    switch (op_arit_cond) {
                        case "<":
                            //codigo_ensamblador.add("jb salto" + salto);    
                            codigo_ensamblador.add("jnb Salto" + salto);
                            break;
                        case ">":
                            //codigo_ensamblador.add("ja salto" + salto);
                            codigo_ensamblador.add("jna Salto" + salto);
                            break;
                        case ">=":
                            //codigo_ensamblador.add("jae salto" + salto);
                            codigo_ensamblador.add("jnae Salto" + salto);
                            break;
                        case "<=":
                            //codigo_ensamblador.add("jbe salto" + salto);
                            codigo_ensamblador.add("jnbe Salto" + salto);
                            break;
                        case "==":
                            //codigo_ensamblador.add("jz salto" + salto);
                            codigo_ensamblador.add("jne Salto" + salto);
                            break;
                        case "!=":
                            //codigo_ensamblador.add("jne salto" + salto);  
                            codigo_ensamblador.add("je Salto" + salto);
                            break;
                    }
                    break;
                case "per":
                    Matcher op_inc = op_decremento.matcher(linea);                    
                    while (matcher.find()) {
                        if (matcher.group().matches(ID.pattern())) {
                            tokens_per.add(matcher.group(1));
                        } else {
                            tokens_per.add(matcher.group());
                        }
                    }
                    //Verificamos si se incrementa o decrementa                    
                    while (op_inc.find()) {
                        if (op_inc.group().trim().equals("++")) {                
                            //caso de que sea incremento    
                            int cont2 = 1;
                            while (cont2 < 4) {  //verificamos si es constante o ID
                                if (tokens_per.get(cont2).matches("([a-z]+)")) {
                                    if (cont2 == 1) {
                                        aux = tokens_per.get(cont2);
                                        if (var_leidas.contains(tokens_per.get(cont2))) {
                                            codigo_ensamblador.add("mov Al, " + aux + " +2");
                                        } else {
                                            codigo_ensamblador.add("mov Al, " + aux);
                                        }
                                        codigo_ensamblador.add("sub Al, '0'");
                                    } else {
                                        codigo_ensamblador.add("xor Cx, Cx");
                                        if (var_leidas.contains(tokens_per.get(cont2))) {
                                            codigo_ensamblador.add("mov Si, offset " + tokens_per.get(cont2) + " +2");
                                        } else {
                                            codigo_ensamblador.add("mov Si, offset " + tokens_per.get(cont2));
                                        }
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si]");
                                        codigo_ensamblador.add("sub Cl, '0'\n");
                                    }
                                } else {
                                    variables.add("Var" + cont + " db '" + tokens_per.get(cont2) + "', '$'");
                                    if (cont2 == 1) {
                                        aux = "Var" + cont;
                                        codigo_ensamblador.add("mov Al, " + aux);
                                        codigo_ensamblador.add("sub Al, '0'");
                                        cont++;
                                    } else {
                                        codigo_ensamblador.add("xor Cx, Cx");
                                        codigo_ensamblador.add("mov Si, offset " + "Var" + cont);
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si]");
                                        codigo_ensamblador.add("sub Cl, '0'\n");
                                        cont++;
                                    }
                                }
                                cont2 = cont2 + 2;
                            }
                            codigo_ensamblador.add("sub Cl, Al");
                            codigo_ensamblador.add("add Cl, 1\n");
                            //asignamos valor a j para simular el funcionamiento de un for
                            if (tokens_per.get(1).matches(numero_ent.pattern())) {
                                codigo_ensamblador.add("mov byte ptr [" + tokens_per.get(0) + "], " + tokens_per.get(1));
                                codigo_ensamblador.add("add " + tokens_per.get(0) + ", 48\n");
                                actualizadas.add(tokens_per.get(0));
                            } else {
                                if (actualizadas.contains(tokens_per.get(1))) {
                                    codigo_ensamblador.add("mov al, [" + tokens_per.get(1) + "]");
                                } else {
                                    codigo_ensamblador.add("mov al, [" + tokens_per.get(1) + "+2]");
                                }
                                codigo_ensamblador.add("mov [" + tokens_per.get(0) + "], al\n");
                                actualizadas.add(tokens_per.get(0));
                            }
                            //etiqueta de salto
                            codigo_ensamblador.add("SaltoPer" + contPer + ":\n");      
                            codigo_ensamblador.add("push Cx");
                        } else {
                            //caso que sea decremento                          
                            incremento = false;
                            int cont2 = 1;
                            while (cont2 < 4) {
                                if (tokens_per.get(cont2).matches("([a-z]+)")) {//caso para ID
                                    if (cont2 == 3) {
                                        aux = tokens_per.get(cont2);
                                        codigo_ensamblador.add("mov Al, " + aux);
                                        codigo_ensamblador.add("sub Al, '0'");
                                    } else {
                                        codigo_ensamblador.add("xor Cx, Cx");
                                        codigo_ensamblador.add("mov Si, offset " + tokens_per.get(cont2));
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si]");
                                        codigo_ensamblador.add("sub Cl, '0'\n");
                                    }
                                } else {
                                    variables.add("Var" + cont + " db '" + tokens_per.get(cont2) + "', '$'");
                                    if (cont2 == 3) {
                                        aux = "Var" + cont;
                                        codigo_ensamblador.add("mov Al, " + aux);
                                        codigo_ensamblador.add("sub Al, '0'");
                                        cont++;
                                    } else {
                                        codigo_ensamblador.add("xor Cx, Cx");
                                        codigo_ensamblador.add("mov Si, offset " + "Var" + cont);
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si]");
                                        codigo_ensamblador.add("sub Cl, '0'\n");
                                        cont++;
                                    }
                                }
                                cont2 = cont2 + 2;
                            }
                            codigo_ensamblador.add("sub Cl, Al");
                            codigo_ensamblador.add("add Cl, 1\n");
                            if (tokens_per.get(1).matches(numero_ent.pattern())) {
                                codigo_ensamblador.add("mov byte ptr [" + tokens_per.get(0) + "], " + tokens_per.get(1));
                                codigo_ensamblador.add("add " + tokens_per.get(0) + ", 48\n");
                                actualizadas.add(tokens_per.get(0));
                            } else {
                                if (actualizadas.contains(tokens_per.get(1))) {
                                    codigo.add("mov al, [" + tokens_per.get(1) + "]");
                                } else {
                                    codigo_ensamblador.add("mov al, [" + tokens_per.get(1) + "+2]");
                                }
                                codigo_ensamblador.add("mov [" + tokens_per.get(0) + "], al\n");
                                actualizadas.add(tokens_per.get(0));
                            }
                            codigo_ensamblador.add("SaltoPer" + contPer + ":\n");
                            codigo_ensamblador.add("push Cx");
                        }
                    }
                    break;
                case "mien":
                    ArrayList<String> listamien_tokens = new ArrayList<>();
                    Pattern pattern2 = Pattern.compile(op_condicional.pattern());
                    Matcher op_condmien = pattern2.matcher(linea);
                    String op_arit_mien = "";
                    int num_opermien = 0;
                    while (matcher.find()) {
                        if (matcher.group().matches(ID.pattern())) {
                            listamien_tokens.add(matcher.group(1)); //es mi ID sin los palitos
                        } else {
                            listamien_tokens.add(matcher.group());
                        }
                    }
                    codigo_ensamblador.add("SaltoMien" + saltomien + ":");
                    saltomien++;

                    while (num_opermien <= 1) {
                        if (listamien_tokens.get(num_opermien).matches("([a-z]+)")) { //caso para ID
                            if (actualizadas.contains(listamien_tokens.get(num_opermien))) {
                                codigo_ensamblador.add("mov Dx, offset " + listamien_tokens.get(num_opermien));
                            } else {
                                codigo_ensamblador.add("mov Dx, offset " + listamien_tokens.get(num_opermien) + "+2");
                            }
                        } else {
                            variables.add("Var" + cont + " db " + "'" + listamien_tokens.get(num_opermien) + "','$'"); //caso para constantes
                            codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                            cont++;
                        }
                        if (num_opermien == 0) {
                            codigo_ensamblador.add("mov Si, Dx");
                            codigo_ensamblador.add("mov Cl, byte ptr [Si]\n ");
                        } else {
                            codigo_ensamblador.add("mov Si, Dx");
                            codigo_ensamblador.add("mov Ch, byte ptr [Si] \n");
                        }
                        num_opermien++;
                    }

                    codigo_ensamblador.add("cmp Cl,Ch\n");

                    while (op_condmien.find()) {
                        op_arit_mien = op_condmien.group(); // el ultimo operador condicional                                                     
                    }

                    switch (op_arit_mien) {
                        case "<":
                            //codigo_ensamblador.add("jb salto" + salto);    
                            codigo_ensamblador.add("jnb SaltoMien" + saltomien);
                            break;
                        case ">":
                            //codigo_ensamblador.add("ja salto" + salto);
                            codigo_ensamblador.add("jna SaltoMien" + saltomien);
                            break;
                        case ">=":
                            //codigo_ensamblador.add("jae salto" + salto);
                            codigo_ensamblador.add("jnae SaltoMien" + saltomien);
                            break;
                        case "<=":
                            //codigo_ensamblador.add("jbe salto" + salto);
                            codigo_ensamblador.add("jnbe SaltoMien" + saltomien);
                            break;
                        case "==":
                            //codigo_ensamblador.add("jz salto" + salto);
                            codigo_ensamblador.add("jne SaltoMien" + saltomien);
                            break;
                        case "!=":
                            //codigo_ensamblador.add("jne salto" + salto);  
                            codigo_ensamblador.add("je SaltoMien" + saltomien);
                            break;
                    }

                    break;
                case "etiquetas_fin":
                    switch (linea.trim()) {
                        case "finsi":
                            if (flag_else == false) {
                                codigo_ensamblador.add("jmp Salto" + (salto + 1) + "\n");
                                codigo_ensamblador.add("Salto" + salto + ":\n");                                
                            }
                            codigo_ensamblador.add("jmp Salto" + (salto + 1) + "\n");
                            codigo_ensamblador.add("Salto" + (salto+1) + ":\n");                            
                            salto++;
                            flag_else = false; //esta
                            break;
                        case "contrario":
                            codigo_ensamblador.add("jmp Salto" + (salto + 1) + "\n");
                            codigo_ensamblador.add("Salto" + salto + ":\n");                            
                            flag_else = true;
                            break;
                        case "fincontrario":
                            break;
                        case "finper":
                            if (incremento) {
                                codigo_ensamblador.add("inc " + aux);
                                //incrementamos j 
                                codigo_ensamblador.add("pop Cx");
                                codigo_ensamblador.add("inc " + tokens_per.get(0));                                
                                codigo_ensamblador.add("loop SaltoPer" + contPer + "\n");
                            } else {
                                codigo_ensamblador.add("dec " + aux);
                                //decrementamos j 
                                codigo_ensamblador.add("pop Cx");
                                codigo_ensamblador.add("dec " + tokens_per.get(0));                                
                                codigo_ensamblador.add("loop SaltoPer" + contPer + "\n");
                            }
                            contPer++;
                            break;
                        case "finmien":
                            codigo_ensamblador.add("jmp SaltoMien" + (saltomien - 1) + "\n");
                            codigo_ensamblador.add("SaltoMien" + saltomien + ":\n");
                            saltomien++;
                            break;
                    }
                    break;
                case "imprimir":
                    codigo_ensamblador.add("mov Ah,09h");
                    while (matcher.find()) {
                        if (matcher.group().matches(("(\"" + cadena + "\")"))) {
                            variables.add("Var" + cont + " db '" + matcher.group(6) + "$'");
                            codigo_ensamblador.add("mov Dx,offset " + "Var" + cont);
                            codigo_ensamblador.add("int 21h\n");
                            cont++;
                        } else if (matcher.group().matches(ID.pattern())) {
                            //si la variable esta leida o actualizada(asignada) el registro se mantiene en 0
                            if (var_leidas.contains(matcher.group(1)) && actualizadas.contains(matcher.group(1))) {
                                codigo_ensamblador.add("mov Dx, offset " + matcher.group(1));
                            } else if (actualizadas.contains(matcher.group(1))) {
                                codigo_ensamblador.add("mov Dx,offset  " + matcher.group(1));
                            } else {
                                //si no se ha modificado, solo declarado
                                codigo_ensamblador.add("mov Dx, offset " + matcher.group(1) + "+2");
                            }
                            codigo_ensamblador.add("int 21h\n");
                        } else {
                            variables.add("Var" + cont + " db '" + matcher.group() + "$'");
                            codigo_ensamblador.add("mov Dx,offset  " + "Var" + cont);
                            codigo_ensamblador.add("int 21h\n");
                            cont++;
                        }
                    }
                    codigo_ensamblador.add("mov Ah, 09h ");
                    codigo_ensamblador.add("mov Dx,offset salto00");
                    codigo_ensamblador.add("int 21h\n");
                    break;
                case "leer":
                    while (matcher.find()) {
                        codigo_ensamblador.add("mov Ah, 0Ah ");
                        codigo_ensamblador.add("mov Dx,offset " + matcher.group(1));
                        codigo_ensamblador.add("int 21h\n");
                        //salto
                        codigo_ensamblador.add("mov Ah, 09h ");
                        codigo_ensamblador.add("mov Dx,offset salto00");
                        codigo_ensamblador.add("int 21h\n");
                        var_leidas.add(matcher.group(1));
                    }
                    break;
                case "asignacion":
                    ArrayList<String> lista_id = new ArrayList<>();
                    String op_arit = "";
                    Pattern pattern = Pattern.compile(op_aritmetico.pattern());
                    Matcher matcher2 = pattern.matcher(linea);
                    while (matcher.find()) {
                        if (matcher.group().matches(ID.pattern())) {
                            lista_id.add(matcher.group(1));

                        } else {
                            lista_id.add(matcher.group());
                        }
                    }
                    //si la lista tiene mas de dos elementos, es una operacion aritmetica
                    if (lista_id.size() > 2) {
                        while (matcher2.find()) {
                            op_arit = matcher2.group(); // el ultimo operando                                
                        }
                        switch (op_arit) {
                            case "+":
                                int numero_oper = 1;
                                codigo_ensamblador.add("xor Cx, Cx");
                                while (numero_oper <= 2) {
                                    if (lista_id.get(numero_oper).matches("([a-z]+)")) {
                                        if (var_leidas.contains(lista_id.get(numero_oper))) {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper) + "+2");
                                        } else {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper));
                                        }
                                    } else {
                                        variables.add("Var" + cont + " db " + "'" + lista_id.get(numero_oper) + "','$'");
                                        codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                                        cont++;
                                    }
                                    if (numero_oper == 1) {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Cl, 48\n");
                                    } else {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Ch, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Ch, 48\n");
                                    }
                                    numero_oper++;
                                }
                                //Hacemos operacion de suma
                                codigo_ensamblador.add("mov " + lista_id.get(0) + ", Cl");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", Ch");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                                actualizadas.add(lista_id.get(0));
                                break;
                            case "-":
                                numero_oper = 1;
                                codigo_ensamblador.add("xor Cx, Cx");
                                while (numero_oper <= 2) {
                                    if (lista_id.get(numero_oper).matches("([a-z]+)")) {
                                        if (var_leidas.contains(lista_id.get(numero_oper))) {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper) + "+2");
                                        } else {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper));
                                        }
                                    } else {
                                        variables.add("Var" + cont + " db " + "'" + lista_id.get(numero_oper) + "','$'");
                                        codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                                        cont++;
                                    }
                                    if (numero_oper == 1) {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Cl, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Cl, 48\n");
                                    } else {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Ch, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Ch, 48\n");
                                    }
                                    numero_oper++;
                                }
                                codigo_ensamblador.add("xor " + lista_id.get(0) + ", 0");
                                codigo_ensamblador.add("mov " + lista_id.get(0) + ", Cl");
                                codigo_ensamblador.add("sub " + lista_id.get(0) + ", Ch");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                                actualizadas.add(lista_id.get(0));
                                break;
                            case "*":
                                numero_oper = 1;
                                while (numero_oper <= 2) {
                                    if (lista_id.get(numero_oper).matches("([a-z]+)")) {
                                        if (var_leidas.contains(lista_id.get(numero_oper))) {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper) + "+2");
                                        } else {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper));
                                        }
                                    } else {
                                        variables.add("Var" + cont + " db " + "'" + lista_id.get(numero_oper) + "','$'");
                                        codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                                        cont++;
                                    }
                                    if (numero_oper == 1) {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Al, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Al, 48\n");
                                    } else {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Ah, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Ah, 48\n");
                                    }
                                    numero_oper++;
                                }
                                codigo_ensamblador.add("mul Ah ");
                                codigo_ensamblador.add("mov " + lista_id.get(0) + ", Al");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                                actualizadas.add(lista_id.get(0));
                                break;
                            case "/":
                                numero_oper = 1;
                                codigo_ensamblador.add("xor Ax, Ax ");
                                codigo_ensamblador.add("xor Bx, Bx ");

                                while (numero_oper <= 2) {
                                    if (lista_id.get(numero_oper).matches("([a-z]+)")) {
                                        if (var_leidas.contains(lista_id.get(numero_oper))) {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper) + "+2");
                                        } else {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper));
                                        }
                                    } else {
                                        variables.add("Var" + cont + " db " + "'" + lista_id.get(numero_oper) + "','$'");
                                        codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                                        cont++;
                                    }
                                    if (numero_oper == 1) {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Al, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Al, 48\n");
                                    } else {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Bl, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Bl, 48\n");
                                    }
                                    numero_oper++;
                                }
                                codigo_ensamblador.add("div Bl ");
                                codigo_ensamblador.add("mov " + lista_id.get(0) + ", Al");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                                actualizadas.add(lista_id.get(0));
                                break;
                            case "%":
                                numero_oper = 1;
                                codigo_ensamblador.add("xor Ax, Ax ");
                                codigo_ensamblador.add("xor Bx, Bx ");

                                while (numero_oper <= 2) {
                                    if (lista_id.get(numero_oper).matches("([a-z]+)")) {
                                        if (var_leidas.contains(lista_id.get(numero_oper))) {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper) + "+2");
                                        } else {
                                            codigo_ensamblador.add("mov Dx, offset " + lista_id.get(numero_oper));
                                        }
                                    } else {
                                        variables.add("Var" + cont + " db " + "'" + lista_id.get(numero_oper) + "','$'");
                                        codigo_ensamblador.add("mov Dx, offset " + "Var" + cont);
                                        cont++;
                                    }
                                    if (numero_oper == 1) {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Al, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Al, 48\n");
                                    } else {
                                        codigo_ensamblador.add("mov Si, Dx");
                                        codigo_ensamblador.add("mov Bl, byte ptr [Si] ");
                                        codigo_ensamblador.add("sub Bl, 48\n");
                                    }
                                    numero_oper++;
                                }
                                codigo_ensamblador.add("div Bl ");
                                codigo_ensamblador.add("mov " + lista_id.get(0) + ", Ah");
                                codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                                actualizadas.add(lista_id.get(0));
                                break;
                        }
                    } else {
                        if (lista_id.get(1).matches(numero_ent.pattern())) {
                            codigo_ensamblador.add("mov byte ptr [" + lista_id.get(0) + "], " + lista_id.get(1));
                            codigo_ensamblador.add("add " + lista_id.get(0) + ", 48\n");
                            actualizadas.add(lista_id.get(0)); // cuando se asigna, se actualiza por lo que va a nuestra lista de actualizadas
                        } else {
                            codigo_ensamblador.add("mov al, [" + lista_id.get(1) + "+2]");
                            codigo_ensamblador.add("mov [" + lista_id.get(0) + "], al\n");
                        }
                    }
                    break;
            }
        }        
        codigo_ensamblador.add("mov Ah, 4Ch");
        codigo_ensamblador.add("int 21h");
        codigo_ensamblador.add(".DATA");
        codigo_ensamblador.addAll(variables);
        codigo_ensamblador.add(".STACK");
        codigo_ensamblador.add("END Inicio");

        ArchivoEnsamblador(codigo_ensamblador, "src\\analizador_lexico_definitivo2\\Ensamblador.asm");
    }

    public static String Sentencia(String linea) {
        Pattern etiquetas_final = Pattern.compile(espacio + "(contrario|finper|finsi|fincontrario|finmien)" + espacio);
        if (linea.matches(si.pattern())) {
            return "si";
        } else if (linea.matches(per.pattern())) {
            return "per";
        } else if (linea.matches(mien.pattern())) {
            return "mien";
        } else if (linea.matches(imprimir.pattern())) {
            return "imprimir";
        } else if (linea.matches(leer.pattern())) {
            return "leer";
        } else if (linea.matches(asignacion.pattern())) {
            return "asignacion";
        } else if (linea.matches(etiquetas_final.pattern())) {
            return "etiquetas_fin";
        }
        return "";
    }

    public static void ArchivoEnsamblador(ArrayList<String> datos, String nombreArchivo) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(nombreArchivo));
            for (String dato : datos) {
                writer.write(dato);
                writer.newLine();
            }
            writer.close();
        } catch (IOException e) {
        }
    }

    public static void main(String[] args) {
        String salida = "src\\analizador_lexico_definitivo2\\Salida.txt";
        try {
            String archivo = Codigo(archivoEntrada);
            //System.out.println(archivo);
            Analizar(archivo);
            //  tiposDeVariables.forEach((key, value) -> System.out.println("Variable: " + key + ", Tipo de dato: " + value));                
            guardarSalida(salida, archivo_limpio());
            String archivo_limpio = Codigo(salida);
            //Eliminamos comentarios, tabulaciones y espacios
            String mediolimpio = "";
            String comen = archivo.replaceAll("//.*", "");
            mediolimpio = comen.replaceAll("[ \t]+", " ");
            Analizador_Sintactico(separarLinea(archivo_limpio), separarLinea(mediolimpio));
            Analizador_Semantico(separarLinea(archivo_limpio), separarLinea(mediolimpio));
            //TablaD.forEach((key, value) -> System.out.println("Error: " + value + ", en la linea: " + key));                               
            for (TDA tda : TablaD) {
                System.out.println("Error: " + tda.sentencia + ", en la linea: " + tda.indice_linea);
            }
            if (TablaD.isEmpty()) {
                //armar txt para ensamblador          
                Ensamblador(separarLinea(archivo_limpio));
            }
        } catch (IOException ex) {
            System.out.println(ex);
        }
    }
}
