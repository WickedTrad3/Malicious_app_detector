class decompile{  
    public static void main(String args[]){  
        boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
        ProcessBuilder processBuilder = new ProcessBuilder();
        if (isWindows) {
            //windows
            processBuilder.command("cmd.exe", "/c", "start ./jadx/bin/jadx.bat " + args[0] + "  && java -jar ./apktool/apktool d " + args[0]);
        }
        else {
            processBuilder.command("bash", "-c", "./jadx/bin/jadx" + args[0] + "&& ./apktool/apktool d"+ args[0]);
        }
        System.out.println("program ran");
        Process process = processBuilder.start();


    }
}