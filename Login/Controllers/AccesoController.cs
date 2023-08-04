using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using Login.Models;
using System.Data;
using System.Data.SqlClient;
using System.Web.Services.Description;

namespace Login.Controllers
{
    public class AccesoController : Controller
    {


        private string connection = "Server=LAPTOP-66E58GR2\\SQLEXPRESS;Database= DB_Acceso;Trusted_Connection=true;Encrypt=False";

        // GET: Acceso
        public ActionResult Login()
        {
            return View();
        }
        public ActionResult Registrar()
        {
            return View();
        }


        [HttpPost]
        public ActionResult Registrar(Usuario oUsuario)
        {

            bool registrado;
            string mensaje;

            if (oUsuario.clave == oUsuario.ConfirmarClave)
            {
                //actualizar clave para encriptar
                oUsuario.clave = EncriptarSha256(oUsuario.clave);
            }
            else
            {
                ViewData["Mensaje"] = "Las contraseñas no coinciden";
                return View();
            }

            using (SqlConnection cn = new SqlConnection(connection))
            {

                SqlCommand cmd = new SqlCommand("sp_RegistrarUsuario", cn);
                cmd.Parameters.AddWithValue("Correo", oUsuario.Correo);
                cmd.Parameters.AddWithValue("Clave", oUsuario.clave);
                cmd.Parameters.Add("Registrado", SqlDbType.Bit).Direction = ParameterDirection.Output;
                cmd.Parameters.Add("Mensaje", SqlDbType.VarChar,100).Direction = ParameterDirection.Output;
                cmd.CommandType = CommandType.StoredProcedure;

                cn.Open();
                cmd.ExecuteNonQuery();
                registrado = Convert.ToBoolean(cmd.Parameters["Registrado"].Value);
                mensaje = cmd.Parameters["Mensaje"].Value.ToString();


            }

            ViewData["Mensaje"] =mensaje;

            if (registrado)
            {
                return RedirectToAction("Login", "Acceso");

            }
            else
            {
                return View();

            }

        }

        [HttpPost]
        public ActionResult Login(Usuario oUsuario)
        {

            oUsuario.clave = EncriptarSha256(oUsuario.clave);
            
            using (SqlConnection cn = new SqlConnection(connection))
            {

                SqlCommand cmd = new SqlCommand("sp_ValidarUsuario", cn);
                cmd.Parameters.AddWithValue("Correo", oUsuario.Correo);
                cmd.Parameters.AddWithValue("Clave", oUsuario.clave);
                cmd.CommandType = CommandType.StoredProcedure;

                cn.Open();
                //lee la primera fila y la primera columna
                oUsuario.IdUsuario= Convert.ToInt32(cmd.ExecuteScalar().ToString());
            }
            if (oUsuario.IdUsuario != 0)
            {
                Session["usuario"] = oUsuario;
                return RedirectToAction("Index", "Home");

            }
            else
            {

                ViewData["Mensaje"] = "usuario no encontrado";
                return View();
            }









            
        }



        //encriptar password
        public static string EncriptarSha256(string text)
        {
            StringBuilder stringBuilder = new StringBuilder();
            using (SHA256 hash =SHA256Managed.Create())
            {
                Encoding enc = Encoding.UTF8;
                byte[] result = hash.ComputeHash(enc.GetBytes(text));
                foreach (byte b in result)
                {
                    stringBuilder.Append(b.ToString("x2"));
                }
                return stringBuilder.ToString();
            }
        }

    }
}