// operjoin module by typobox43

#include "users.h"
#include "channels.h"
#include "modules.h"

/* $ModDesc: Forces opers to join a specified channel on oper-up */

Server *Srv;

class ModuleOperjoin : public Module {

	private:

		std::string operChan;
		ConfigReader* conf;

	public:

		ModuleOperjoin() {

			Srv = new Server;
			conf = new ConfigReader;

			operChan = conf->ReadValue("operjoin", "channel", 0);

		}

		virtual ~ModuleOperjoin() {

			delete Srv;
			delete conf;

		}

		virtual Version GetVersion() {

			return Version(1,0,0,1);

		}

		virtual void OnOper(userrec* user) {

			if(operChan != "") {

				Srv->JoinUserToChannel(user,operChan,"");

			}

		}

};

class ModuleOperjoinFactory : public ModuleFactory
{
 public:
        ModuleOperjoinFactory()
        {
        }

        ~ModuleOperjoinFactory()
        {
        }

        virtual Module * CreateModule()
        {
                return new ModuleOperjoin;
        }

};

extern "C" void * init_module( void )
{
        return new ModuleOperjoinFactory;
}

